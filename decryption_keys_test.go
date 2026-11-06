package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/xml"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"
)

// The signed samltest.id ArtifactResponse and the Okta POST response in
// testdata both carry an assertion encrypted to sp_key.pem: the first wraps
// the content key inside EncryptedData, the second beside it. key_2017.pem
// is another key, standing in for the key an SP is rotating away from.

func testKey(t *testing.T, name string) *rsa.PrivateKey {
	t.Helper()
	return mustParsePrivateKey(golden.Get(t, name)).(*rsa.PrivateKey)
}

// rotatingSP is a service provider for the fixture whose IdP metadata is in
// metadataFile, at the moment now, with key as Key and extra as
// DecryptionKeys.
func rotatingSP(t *testing.T, now time.Time, metadataFile string, key *rsa.PrivateKey, extra []*rsa.PrivateKey) *ServiceProvider {
	t.Helper()
	// NewServiceProviderTest sets the clocks, so it runs before they are pinned.
	certificate := NewServiceProviderTest(t).Certificate
	TimeNow = func() time.Time { return now }
	Clock = dsig.NewFakeClockAt(now)
	sp := &ServiceProvider{
		Key:            key,
		DecryptionKeys: extra,
		Certificate:    certificate,
		MetadataURL:    mustParseURL("http://localhost:8000/saml/metadata"),
		AcsURL:         mustParseURL("http://localhost:8000/saml/acs"),
		IDPMetadata:    &EntityDescriptor{},
	}
	assert.NilError(t, xml.Unmarshal(golden.Get(t, metadataFile), sp.IDPMetadata))
	return sp
}

func parseArtifactResponse(t *testing.T, key *rsa.PrivateKey, extra []*rsa.PrivateKey) (*Assertion, error) {
	t.Helper()
	now, err := time.Parse(timeFormat, "2021-08-17T10:26:57Z")
	assert.NilError(t, err)
	sp := rotatingSP(t, now, "TestGetArtifactBindingLocation_IDPMetadata", key, extra)
	return sp.ParseXMLArtifactResponse(golden.Get(t, "TestParseXMLArtifactResponse_response"),
		[]string{"id-f3c7bc7d626a4ededa6028b718e5252c6e770b94"}, "id-218eb155248f7db7c85fe4e2709a3f17a70d09c7", sp.AcsURL)
}

func parsePostResponse(t *testing.T, key *rsa.PrivateKey, extra []*rsa.PrivateKey) (*Assertion, error) {
	t.Helper()
	now, err := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Tue Mar 3 19:24:28 UTC 2020")
	assert.NilError(t, err)
	sp := rotatingSP(t, now, "TestSPCanHandleOktaSignedResponseEncryptedAssertion_IDPMetadata", key, extra)
	response := string(golden.Get(t, "TestSPCanHandleOktaSignedResponseEncryptedAssertion_response"))
	req := http.Request{PostForm: url.Values{"SAMLResponse": {response}}, URL: &sp.AcsURL}
	return sp.ParseResponse(&req, []string{"id-a7364d1e4432aa9085a7a8bd824ea2fa8fa8f684"})
}

func privateReason(t *testing.T, err error) string {
	t.Helper()
	ire, ok := err.(*InvalidResponseError)
	assert.Assert(t, ok, "got %v", err)
	return ire.PrivateErr.Error()
}

// An assertion encrypted to a key in DecryptionKeys decrypts, on both the
// artifact and the POST binding.
func TestAssertionDecryptsWithAnExtraKey(t *testing.T) {
	spKey := testKey(t, "sp_key.pem")

	assertion, err := parseArtifactResponse(t, testKey(t, "key_2017.pem"), []*rsa.PrivateKey{spKey})
	assert.Assert(t, err == nil, "%v", err)
	assert.Check(t, assertion.Subject != nil && assertion.Subject.NameID != nil)

	assertion, err = parsePostResponse(t, testKey(t, "key_2017.pem"), []*rsa.PrivateKey{spKey})
	assert.Assert(t, err == nil, "%v", err)
	assert.Check(t, is.Equal("testuser@testrsc.com", assertion.Subject.NameID.Value))
}

// Key is tried first: an assertion encrypted to it decrypts whatever the
// extra keys are.
func TestAssertionDecryptsWithKeyBeforeExtraKeys(t *testing.T) {
	_, err := parseArtifactResponse(t, testKey(t, "sp_key.pem"), []*rsa.PrivateKey{testKey(t, "key_2017.pem")})
	assert.NilError(t, err)
}

// When no key fits, the error says how many keys were tried and nothing
// about them.
func TestAssertionRefusedWhenNoKeyFits(t *testing.T) {
	// idp_key.pem is the same key as sp_key.pem, so the stranger is generated.
	stranger, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	keys := []*rsa.PrivateKey{stranger}

	_, err = parseArtifactResponse(t, testKey(t, "key_2017.pem"), keys)
	assert.Check(t, is.Equal(privateReason(t, err),
		"failed to decrypt EncryptedAssertion: no key decrypted it, of 2 tried"))

	_, err = parsePostResponse(t, testKey(t, "key_2017.pem"), keys)
	assert.Check(t, is.Equal(privateReason(t, err),
		"failed to decrypt EncryptedAssertion: failed to decrypt key from response: no key decrypted it, of 2 tried"))
}

// Without DecryptionKeys the refusal is exactly what it was before them.
func TestAssertionRefusalUnchangedWithoutExtraKeys(t *testing.T) {
	_, err := parseArtifactResponse(t, testKey(t, "key_2017.pem"), nil)
	assert.Check(t, is.Equal(privateReason(t, err),
		"failed to decrypt EncryptedAssertion: certificate does not match provided key"))
}

// An EncryptedAssertion with no EncryptedKey anywhere has no wrapped key for
// DecryptionKeys to open, so they change nothing: it is refused exactly as
// with Key alone.
func TestEncryptedAssertionWithoutEncryptedKeyIgnoresExtraKeys(t *testing.T) {
	el := etree.NewElement("EncryptedAssertion")
	data := el.CreateElement("xenc:EncryptedData")
	data.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
	data.CreateElement("xenc:EncryptionMethod").CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#aes128-cbc")
	data.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").SetText("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")

	without := ServiceProvider{Key: testKey(t, "sp_key.pem")}
	_, errWithout := without.decryptElement(el)
	with := ServiceProvider{Key: testKey(t, "sp_key.pem"), DecryptionKeys: []*rsa.PrivateKey{testKey(t, "key_2017.pem")}}
	_, errWith := with.decryptElement(el)

	assert.Check(t, is.Error(errWithout, "expected key to be []byte"))
	assert.Check(t, is.Error(errWith, "expected key to be []byte"))
}
