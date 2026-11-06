# Supatype's maintained fork of crewjam/saml

This is the SAML library [Supatype](https://github.com/supatype) runs in
production, maintained as a fork of
[crewjam/saml](https://github.com/crewjam/saml). Import it as
`github.com/supatype/saml`. Use upstream instead if it is maintained again
and carries the fixes listed below.

## Why it exists

Upstream's last commit was on 2025-05-09. Security pull requests have sat
unreviewed since February 2026, and
[GO-2026-6909](https://pkg.go.dev/vuln/GO-2026-6909), published on
2026-11-05, affects every upstream version with no fixed release. A signed
assertion could have its subject `NameID` read from an element in another
XML namespace, which can sign a user in as someone else.

## What it carries

The fork starts from upstream commit
[`3465403`](https://github.com/crewjam/saml/commit/346540312f721498fc75e69637d9250dd89f230b),
which is `v0.5.1` plus three commits. On top of that, in order:

1. The module path changes to `github.com/supatype/saml`.
2. [crewjam/saml#674](https://github.com/crewjam/saml/pull/674): binds
   `NameID`, `Conditions` and the subject confirmation elements to the
   assertion namespace, and refuses assertions missing `Subject`,
   `Conditions` or `SubjectConfirmationData` instead of panicking. This
   fixes GO-2026-6909.
3. Statements and attributes are bound to the assertion namespace too.
   #674 left them open, so an `Attribute` in another namespace could still
   supply the `subject-id` that many service providers identify users by.
   `ProxyRestriction` also parses now.
4. goxmldsig moves to v1.6.1, for CVE-2026-33487 and GHSA-qhrp-hfff-vphr,
   following [#663](https://github.com/crewjam/saml/pull/663) and
   [#664](https://github.com/crewjam/saml/pull/664). The other
   dependencies move to their latest releases, so Go 1.26 is required.
5. Signatures on assertions with more than 1000 elements validate again
   instead of panicking, ported from
   [grafana/saml#89](https://github.com/grafana/saml/pull/89).
6. [crewjam/saml#659](https://github.com/crewjam/saml/pull/659): with
   `AllowIDPInitiated` set, a present `InResponseTo` is still checked, so
   an SP-initiated response cannot be replayed as an IdP-initiated one.
7. Malformed ciphertext in an encrypted assertion returns an error instead
   of panicking, and `tripledes-cbc`, which was really single DES and never
   decrypted, is no longer offered.
8. Assertions must carry a bearer `SubjectConfirmation` and an
   `AudienceRestriction`, as the SAML web browser SSO profile requires.
9. RSA PKCS#1 v1.5 key transport is no longer decrypted, because it is open
   to padding-oracle attacks. RSA-OAEP, which SP metadata advertises, is.
10. [crewjam/saml#646](https://github.com/crewjam/saml/pull/646): the
    xmlenc fuzz test key is no longer compiled into every binary.
11. CI runs vet, race-enabled tests, govulncheck and golangci-lint.
12. A daily workflow watches upstream, described below.
13. [crewjam/saml#668](https://github.com/crewjam/saml/pull/668): the
    setup instructions point at samltest.dev, because samltest.id is
    compromised.

Items 3 and 7 to 9 are this fork's own changes, not yet proposed upstream.

## Upstream pull requests reviewed

| Pull request | Verdict | Why |
| --- | --- | --- |
| [#674](https://github.com/crewjam/saml/pull/674) namespace binding, GO-2026-6909 | Carried | Fixes the advisory. Incomplete for attributes, which item 3 covers. |
| [#658](https://github.com/crewjam/saml/pull/658) KeyInfo injection | Not carried | Withdrawn by its author: goxmldsig already checks KeyInfo certificates against the trusted ones. |
| [#659](https://github.com/crewjam/saml/pull/659) AllowIDPInitiated bypass | Carried | Closes a replay of SP-initiated responses. |
| [#660](https://github.com/crewjam/saml/pull/660) require Destination | Not carried | The required audience and Recipient checks already bind a response to this SP. It would refuse some IdPs' valid unsigned responses. |
| [#662](https://github.com/crewjam/saml/pull/662), [#663](https://github.com/crewjam/saml/pull/663), [#664](https://github.com/crewjam/saml/pull/664) goxmldsig v1.6.0 | Carried as item 4 | #662 also changes samlsp sessions, which is not taken. |
| [#669](https://github.com/crewjam/saml/pull/669), [grafana/saml#89](https://github.com/grafana/saml/pull/89) large assertions | Carried as item 5 | Needed once goxmldsig v1.6.1 limits traversal. |
| [#671](https://github.com/crewjam/saml/pull/671) more digest and AES-GCM URIs | Not carried | Lets more encrypted assertions decrypt. A compatibility change, not a security one. |
| [#672](https://github.com/crewjam/saml/pull/672), [#673](https://github.com/crewjam/saml/pull/673) GCM encryption | Not carried | They fix encrypting, which only an identity provider does. |
| [#646](https://github.com/crewjam/saml/pull/646) fuzz key | Carried | Also carried by posit-dev/crewjam-saml. |
| [#668](https://github.com/crewjam/saml/pull/668) samltest.id | Carried | The domain is compromised. |
| [#611](https://github.com/crewjam/saml/pull/611) NameID comments | Not needed | `NameID` text is already read in full around comments. |

[posit-dev/crewjam-saml](https://github.com/posit-dev/crewjam-saml) carries
only #646. [grafana/saml](https://github.com/grafana/saml) carries #89,
taken here, and changes to logout and IdP-initiated flows that this fork's
users do not need.

## Versions

Releases use ordinary semantic version tags under the new module path,
starting at `v0.6.0`.

## Watching upstream

The new module path means govulncheck no longer reports crewjam/saml
advisories to this fork's users. The `upstream-watch` workflow runs daily.
It checks the Go vulnerability database for `github.com/crewjam/saml` and
`github.com/russellhaering/goxmldsig`, and checks crewjam/saml for new tags,
commits and security-looking pull requests. Anything not seen before is
posted to the open `upstream-watch` issue, or opens one.

[@nic-jennings](https://github.com/nic-jennings) acts on those issues. For
each item:

- an advisory: check whether this fork is affected, fix it here and
  release;
- a commit, tag or pull request: decide whether to carry it, and record
  the decision in the table above.

Then close the issue, or add the item's key to
`.github/upstream-watch/acknowledged.txt`.

## Reporting a security issue

Report it privately through this repository's
[security advisories](https://github.com/supatype/saml/security/advisories/new),
not in the issue tracker.

---

# SAML

[![Go Reference](https://pkg.go.dev/badge/github.com/supatype/saml.svg)](https://pkg.go.dev/github.com/supatype/saml)

![Build Status](https://github.com/supatype/saml/actions/workflows/test.yml/badge.svg)

Package saml contains a partial implementation of the SAML standard in golang.
SAML is a standard for identity federation, i.e. either allowing a third party to authenticate your users or allowing third parties to rely on us to authenticate their users.

## Introduction

In SAML parlance an **Identity Provider** (IDP) is a service that knows how to authenticate users. A **Service Provider** (SP) is a service that delegates authentication to an IDP. If you are building a service where users log in with someone else's credentials, then you are a **Service Provider**. This package supports implementing both service providers and identity providers.

The core package contains the implementation of SAML. The package samlsp provides helper middleware suitable for use in Service Provider applications. The package samlidp provides a rudimentary IDP service that is useful for testing or as a starting point for other integrations.

## Getting Started as a Service Provider

Let us assume we have a simple web application to protect. We'll modify this application so it uses SAML to authenticate users.

```golang
package main

import (
    "fmt"
    "net/http"
)

func hello(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello, World!")
}

func main() {
    app := http.HandlerFunc(hello)
    http.Handle("/hello", app)
    http.ListenAndServe(":8000", nil)
}
```

Each service provider must have an self-signed X.509 key pair established. You can generate your own with something like this:

    openssl req -x509 -newkey rsa:2048 -keyout myservice.key -out myservice.cert -days 365 -nodes -subj "/CN=myservice.example.com"

We will use `samlsp.Middleware` to wrap the endpoint we want to protect. Middleware provides both an `http.Handler` to serve the SAML specific URLs **and** a set of wrappers to require the user to be logged in. We also provide the URL where the service provider can fetch the metadata from the IDP at startup. In our case, we'll use [samltest.dev](https://www.samltest.dev/), an identity provider designed for testing.

samltest.dev gives each app its own IDP, so first create an app with at least one test user. You can do this on the website or with the [API](https://www.samltest.dev/#api):

    curl -X POST https://www.samltest.dev/api/apps \
      -H "Content-Type: application/json" \
      -d '{"users":[{"email":"john@example.com","firstName":"John","lastName":"Doe"}]}'

The response contains the app's ID (for example `app_01kg2nmcmp9gey67b0kxpqm643`). The IDP metadata URL for the app is `https://www.samltest.dev/apps/<APP_ID>/metadata`.

```golang
package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"

	"github.com/supatype/saml/samlsp"
)

func hello(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %s!", samlsp.AttributeFromContext(r.Context(), "displayName"))
}

func main() {
	keyPair, err := tls.LoadX509KeyPair("myservice.cert", "myservice.key")
	if err != nil {
		panic(err) // TODO handle error
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err) // TODO handle error
	}

	idpMetadataURL, err := url.Parse("https://www.samltest.dev/apps/<APP_ID>/metadata")
	if err != nil {
		panic(err) // TODO handle error
	}
	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient,
		*idpMetadataURL)
	if err != nil {
		panic(err) // TODO handle error
	}

	rootURL, err := url.Parse("http://localhost:8000")
	if err != nil {
		panic(err) // TODO handle error
	}

	samlSP, _ := samlsp.New(samlsp.Options{
		URL:            *rootURL,
		Key:            keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:    keyPair.Leaf,
		IDPMetadata: idpMetadata,
	})
	app := http.HandlerFunc(hello)
	http.Handle("/hello", samlSP.RequireAccount(app))
	http.Handle("/saml/", samlSP)
	http.ListenAndServe(":8000", nil)
}
```

Next we'll have to register our service provider with the identity provider to establish trust from the service provider to the IDP. samltest.dev doesn't take an uploaded metadata file. Instead, set the app's SP ACS URL and SP Entity ID, either under "SAML SP Settings" on `https://www.samltest.dev/apps/<APP_ID>` or with the API:

    curl -X PUT https://www.samltest.dev/api/apps/<APP_ID> \
      -H "Content-Type: application/json" \
      -d '{"users":[{"email":"john@example.com","firstName":"John","lastName":"Doe"}],
           "spAcsUrl":"http://localhost:8000/saml/acs",
           "spEntityId":"http://localhost:8000/saml/metadata"}'

By default `samlsp` uses `<root URL>/saml/acs` as the ACS URL and `<root URL>/saml/metadata` as the entity ID. You can view the service provider's metadata at `localhost:8000/saml/metadata`.

Now you should be able to authenticate. The flow should look like this:

1. You browse to `localhost:8000/hello`

1. The middleware redirects you to `https://www.samltest.dev/apps/<APP_ID>/login`

1. samltest.dev asks which of the app's test users you want to log in as. There is no password.

1. samltest.dev returns you an HTML document which contains an HTML form setup to POST to `localhost:8000/saml/acs`. The form is automatically submitted if you have javascript enabled.

1. The local service validates the response, issues a session cookie, and redirects you to the original URL, `localhost:8000/hello`.

1. This time when `localhost:8000/hello` is requested there is a valid session and so the main content is served.

## Getting Started as an Identity Provider

Please see `example/idp/` for a substantially complete example of how to use the library and helpers to be an identity provider.

## Support

The SAML standard is huge and complex with many dark corners and strange, unused features. This package implements the most commonly used subset of these features required to provide a single sign on experience. The package supports at least the subset of SAML known as [interoperable SAML](https://kantarainitiative.github.io/SAMLprofiles/saml2int.html).

This package supports the **Web SSO** profile. Message flows from the service provider to the IDP are supported using the **HTTP Redirect** binding and the **HTTP POST** binding. Message flows from the IDP to the service provider are supported via the **HTTP POST** binding.

The package can produce signed SAML assertions, and can validate both signed and encrypted SAML assertions.

## RelayState

The _RelayState_ parameter allows you to pass user state information across the authentication flow. The most common use for this is to allow a user to request a deep link into your site, be redirected through the SAML login flow, and upon successful completion, be directed to the originally requested link, rather than the root.

Unfortunately, _RelayState_ is less useful than it could be. Firstly, it is **not** authenticated, so anything you supply must be signed to avoid XSS or CSRF. Secondly, it is limited to 80 bytes in length, which precludes signing. (See section 3.6.3.1 of SAMLProfiles.)

## References

The SAML specification is a collection of PDFs (sadly):

- [SAMLCore](http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf) defines data types.

- [SAMLBindings](http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf) defines the details of the HTTP requests in play.

- [SAMLProfiles](http://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf) describes data flows.

- [SAMLConformance](http://docs.oasis-open.org/security/saml/v2.0/saml-conformance-2.0-os.pdf) includes a support matrix for various parts of the protocol.

[SAMLTest](https://www.samltest.dev/) is a free SAML identity provider and SCIM directory for testing SAML service providers.

## Security Issues

Please do not report security issues in the issue tracker. Report them privately through this repository's [security advisories](https://github.com/supatype/saml/security/advisories/new). If your issue is *not* a security issue, please use the issue tracker so other contributors can help.
