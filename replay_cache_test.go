package saml

import (
	"encoding/xml"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"
)

// memoryReplayCache is an AssertionReplayCache that remembers every ID it is
// given, with the expiry it was given.
type memoryReplayCache map[string]time.Time

func (c memoryReplayCache) Consume(assertionID string, expiresAt time.Time) error {
	if _, seen := c[assertionID]; seen {
		return ErrAssertionReplayed
	}
	c[assertionID] = expiresAt
	return nil
}

type failingReplayCache struct{}

func (failingReplayCache) Consume(string, time.Time) error { return errors.New("store unavailable") }

const oneloginRequestID = "id-d40c15c104b52691eccf0a2a5c8a15595be75423"

// oneloginSP returns a service provider for the signed OneLogin response in
// testdata, with the clock at the moment it was issued, and a function that
// parses that response with it.
func oneloginSP(t *testing.T, cache AssertionReplayCache) func(requestID string) (*Assertion, error) {
	t.Helper()
	test := NewServiceProviderTest(t)
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Tue Jan 5 17:53:12 UTC 2016")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())

	sp := &ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://29ee6d2e.ngrok.io/saml/metadata"),
		AcsURL:      mustParseURL("https://29ee6d2e.ngrok.io/saml/acs"),
		IDPMetadata: &EntityDescriptor{},
		ReplayCache: cache,
	}
	assert.NilError(t, xml.Unmarshal(golden.Get(t, "TestSPCanHandleOneloginResponse_IDPMetadata"), sp.IDPMetadata))
	response := string(golden.Get(t, "TestSPCanHandleOneloginResponse_response"))

	return func(requestID string) (*Assertion, error) {
		req := http.Request{PostForm: url.Values{"SAMLResponse": {response}}, URL: &sp.AcsURL}
		return sp.ParseResponse(&req, []string{requestID})
	}
}

func privateErr(t *testing.T, err error) error {
	t.Helper()
	var ire *InvalidResponseError
	assert.Assert(t, errors.As(err, &ire), "got %v", err)
	return ire.PrivateErr
}

// A response is accepted once; the same response again is refused.
func TestParseResponseRefusesReplay(t *testing.T) {
	cache := memoryReplayCache{}
	parse := oneloginSP(t, cache)

	assertion, err := parse(oneloginRequestID)
	assert.NilError(t, err)
	assert.Check(t, is.Len(cache, 1))
	_, recorded := cache[assertion.ID]
	assert.Check(t, recorded)

	_, err = parse(oneloginRequestID)
	assert.Check(t, errors.Is(privateErr(t, err), ErrAssertionReplayed), "got %v", err)
}

// A response refused for any other reason is not recorded.
func TestParseResponseRecordsNothingWhenRefused(t *testing.T) {
	cache := memoryReplayCache{}
	parse := oneloginSP(t, cache)

	_, err := parse("id-of-another-request")
	assert.Check(t, err != nil)
	assert.Check(t, is.Len(cache, 0))
}

// An error from the cache refuses the response.
func TestParseResponseRefusedWhenTheCacheFails(t *testing.T) {
	_, err := oneloginSP(t, failingReplayCache{})(oneloginRequestID)
	assert.Check(t, is.ErrorContains(privateErr(t, err), "store unavailable"))
}

// The cache is told the last moment the assertion is acceptable: the earliest
// of the issue deadline and each NotOnOrAfter, with the clock skew the
// expiry checks allow.
func TestAcceptableUntil(t *testing.T) {
	now := TimeNow()
	cases := []struct {
		name     string
		edit     func(a *Assertion)
		deadline time.Time
	}{
		{"issue deadline first", func(a *Assertion) {
			a.Conditions.NotOnOrAfter = now.Add(time.Hour)
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotOnOrAfter = now.Add(time.Hour)
		}, now.Add(MaxIssueDelay)},
		{"conditions first", func(a *Assertion) {
			a.Conditions.NotOnOrAfter = now.Add(-150 * time.Second)
		}, now.Add(-150*time.Second + MaxClockSkew)},
		{"confirmation first", func(a *Assertion) {
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotOnOrAfter = now.Add(-150 * time.Second)
		}, now.Add(-150*time.Second + MaxClockSkew)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := validAssertion(now)
			c.edit(a)
			assert.Check(t, is.DeepEqual(acceptableUntil(a), c.deadline))
		})
	}
}
