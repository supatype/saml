package main

import (
	"strings"
	"testing"
)

func TestMarkerRoundTrip(t *testing.T) {
	text := report([]item{{Key: "vuln:GO-2026-6909", Title: "t", URL: "u"}, {Key: "pr:674", Title: "t", URL: "u"}}, "someone")
	got := markerKeys(text)
	if len(got) != 2 || got[0] != "vuln:GO-2026-6909" || got[1] != "pr:674" {
		t.Fatalf("markerKeys(report) = %v", got)
	}
	if !strings.HasPrefix(text, "@someone ") {
		t.Errorf("report does not mention the notify handle: %q", text)
	}
}

func TestFilterUnseen(t *testing.T) {
	items := []item{{Key: "pr:2"}, {Key: "pr:1"}, {Key: "pr:2"}, {Key: "tag:v0.5.1"}}
	got := filterUnseen(items, map[string]bool{"tag:v0.5.1": true})
	if len(got) != 2 || got[0].Key != "pr:1" || got[1].Key != "pr:2" {
		t.Fatalf("filterUnseen = %v", got)
	}
}

func TestLooksSecurityRelated(t *testing.T) {
	for _, title := range []string{
		"Bind assertion elements by namespace and check optional ones for nil (GO-2026-6909)",
		"Fix signature validation bypass via KeyInfo injection",
		"Upgrade goxmldsig to v1.6.0 to fix CVE-2026-33487",
		"Fix nil-pointer panic and traversal limit in signature validation",
		"Fix authentication bypass with AllowIDPInitiated",
	} {
		if !looksSecurityRelated(title) {
			t.Errorf("not flagged: %q", title)
		}
	}
	for _, title := range []string{
		"Bump github.com/google/go-cmp from 0.6.0 to 0.7.0",
		"CookieSessionProvider: add Path",
		"support Scoping",
	} {
		if looksSecurityRelated(title) {
			t.Errorf("flagged: %q", title)
		}
	}
}

func TestReportEscapesBracketsInTitles(t *testing.T) {
	text := report([]item{{Key: "commit:1", Title: "[Issue-582] Log sign in attempts", URL: "u"}}, "")
	if !strings.Contains(text, `- [\[Issue-582\] Log sign in attempts](u)`) {
		t.Fatalf("brackets not escaped: %q", text)
	}
}

func TestPullItemsSkipsDependabotAndUnrelated(t *testing.T) {
	pulls := []pullJSON{
		{Number: 1, Title: "Fix signature validation bypass"},
		{Number: 2, Title: "Bump golang.org/x/crypto", Body: "fixes CVE-2025-1234"},
		{Number: 3, Title: "support Scoping"},
	}
	pulls[1].User.Login = "dependabot[bot]"
	got := pullItems("crewjam/saml", pulls)
	if len(got) != 1 || got[0].Key != "pr:1" {
		t.Fatalf("pullItems = %v", got)
	}
}
