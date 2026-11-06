package main

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// item is one piece of upstream activity.
type item struct {
	Key   string // stable identity, such as "vuln:GO-2026-6909"
	Title string // one line naming it
	URL   string
}

// markerPattern matches the hidden marker report writes for each item.
var markerPattern = regexp.MustCompile(`<!-- upstream-watch:(\S+) -->`)

func marker(key string) string {
	return fmt.Sprintf("<!-- upstream-watch:%s -->", key)
}

// markerKeys returns the keys of every marker in text.
func markerKeys(text string) []string {
	matches := markerPattern.FindAllStringSubmatch(text, -1)
	keys := make([]string, 0, len(matches))
	for _, m := range matches {
		keys = append(keys, m[1])
	}
	return keys
}

func filterUnseen(items []item, seen map[string]bool) []item {
	var unseen []item
	for _, it := range items {
		if !seen[it.Key] {
			unseen = append(unseen, it)
			seen[it.Key] = true // the same item listed twice is reported once
		}
	}
	sort.SliceStable(unseen, func(i, j int) bool { return unseen[i].Key < unseen[j].Key })
	return unseen
}

// report renders unseen items as a Markdown list, one marker per item.
func report(unseen []item, notify string) string {
	var b strings.Builder
	if notify != "" {
		fmt.Fprintf(&b, "@%s ", notify)
	}
	b.WriteString("New upstream activity to review. See the README section " +
		"\"Watching upstream\" for what to do with each kind.\n\n")
	// Upstream titles can hold brackets, which would end the link text early.
	escape := strings.NewReplacer("[", `\[`, "]", `\]`)
	for _, it := range unseen {
		fmt.Fprintf(&b, "- [%s](%s) %s\n", escape.Replace(it.Title), it.URL, marker(it.Key))
	}
	b.WriteString("\nAdd a key to `.github/upstream-watch/acknowledged.txt`, or leave it " +
		"here, and it will not be reported again.\n")
	return b.String()
}

// securityPattern matches pull request titles and bodies that look like
// security fixes. It errs towards matching: a false positive costs a glance.
var securityPattern = regexp.MustCompile(`(?i)\b(security|vulnerab\w*|cve-\d[\d-]*|ghsa-[\w-]+|go-20\d\d-\d+|bypass\w*|inject\w*|forg\w*|spoof\w*|replay\w*|panic\w*|nil[- ]pointer|dereferenc\w*|denial of service|dos|xxe|xsw|signature wrapping|escalat\w*|impersonat\w*|namespace\w*|signature|verif\w*|traversal)\b`)

func looksSecurityRelated(text string) bool {
	return securityPattern.MatchString(text)
}

// vulnItems lists every advisory in the Go vulnerability database for modules.
func vulnItems(ctx context.Context, client *http.Client, modules []string) ([]item, error) {
	index, err := getJSON[[]vulnModuleJSON](ctx, client, "https://vuln.go.dev/index/modules.json", "")
	if err != nil {
		return nil, fmt.Errorf("reading the Go vulnerability database: %w", err)
	}

	watched := map[string]bool{}
	for _, m := range modules {
		watched[m] = true
	}
	var items []item
	for _, mod := range index {
		if !watched[mod.Path] {
			continue
		}
		for _, v := range mod.Vulns {
			fixed := "no fixed version"
			if v.Fixed != "" {
				fixed = "fixed in v" + v.Fixed
			}
			items = append(items, item{
				Key:   "vuln:" + v.ID,
				Title: fmt.Sprintf("%s in %s, %s", v.ID, mod.Path, fixed),
				URL:   "https://pkg.go.dev/vuln/" + v.ID,
			})
		}
	}
	return items, nil
}

// repoItems lists the upstream repository's tags, its default branch's recent
// commits and its security-looking pull requests.
func repoItems(ctx context.Context, gh *gitHub, repo string) ([]item, error) {
	tags, err := ghGet[[]tagJSON](ctx, gh, "/repos/"+repo+"/tags?per_page=100")
	if err != nil {
		return nil, err
	}
	commits, err := ghGet[[]commitJSON](ctx, gh, "/repos/"+repo+"/commits?per_page=100")
	if err != nil {
		return nil, err
	}
	pulls, err := ghGet[[]pullJSON](ctx, gh, "/repos/"+repo+"/pulls?state=all&sort=created&direction=desc&per_page=100")
	if err != nil {
		return nil, err
	}

	items := tagItems(repo, tags)
	items = append(items, commitItems(repo, commits)...)
	return append(items, pullItems(repo, pulls)...), nil
}

func tagItems(repo string, tags []tagJSON) []item {
	items := make([]item, 0, len(tags))
	for _, t := range tags {
		items = append(items, item{
			Key: "tag:" + t.Name, Title: "Tag " + t.Name + " on " + repo,
			URL: "https://github.com/" + repo + "/releases/tag/" + t.Name,
		})
	}
	return items
}

func commitItems(repo string, commits []commitJSON) []item {
	items := make([]item, 0, len(commits))
	for _, c := range commits {
		subject, _, _ := strings.Cut(c.Commit.Message, "\n")
		items = append(items, item{
			Key: "commit:" + c.SHA, Title: fmt.Sprintf("Commit %.7s on %s: %s", c.SHA, repo, subject),
			URL: "https://github.com/" + repo + "/commit/" + c.SHA,
		})
	}
	return items
}

// pullItems keeps the pull requests that look security-related.
func pullItems(repo string, pulls []pullJSON) []item {
	var items []item
	for _, p := range pulls {
		// Dependency bumps quote release notes full of security words, and the
		// fork keeps its own dependencies current.
		if p.User.Login == "dependabot[bot]" || !looksSecurityRelated(p.Title+"\n"+p.Body) {
			continue
		}
		items = append(items, item{
			Key:   fmt.Sprintf("pr:%d", p.Number),
			Title: fmt.Sprintf("Pull request #%d on %s: %s", p.Number, repo, p.Title),
			URL:   p.URL,
		})
	}
	return items
}
