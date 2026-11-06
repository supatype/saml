// Command upstream-watch reports new upstream activity that this fork has not
// seen: Go vulnerability database advisories for the watched modules, and new
// tags, commits and security-looking pull requests on crewjam/saml.
//
// Every item has a key such as "vuln:GO-2026-6909" or "pr:674". A key is seen
// when it is listed in acknowledged.txt or appears in a marker comment in any
// issue labelled upstream-watch, open or closed. Unseen items are added to the
// open upstream-watch issue as a comment, or open a new issue when none is
// open, so one run never opens more than one issue.
//
// Run with -dry-run to print what would be reported without writing anything.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// config is what a run watches and where it reports.
type config struct {
	Upstream     string   // owner/name of the upstream repository
	Fork         string   // owner/name of this repository, where issues go
	Modules      []string // module paths looked up in the Go vulnerability database
	Notify       string   // GitHub handle mentioned on each report
	Acknowledged string   // path of the acknowledged keys file
	DryRun       bool
}

func main() {
	cfg := config{
		Upstream: "crewjam/saml",
		Modules:  []string{"github.com/crewjam/saml", "github.com/russellhaering/goxmldsig"},
	}
	flag.StringVar(&cfg.Fork, "fork", os.Getenv("GITHUB_REPOSITORY"), "owner/name of the repository issues are opened in")
	flag.StringVar(&cfg.Notify, "notify", os.Getenv("WATCH_NOTIFY"), "GitHub handle mentioned on each report")
	flag.StringVar(&cfg.Acknowledged, "acknowledged", "acknowledged.txt", "file of keys already seen")
	flag.BoolVar(&cfg.DryRun, "dry-run", false, "print the report instead of writing it")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	err := run(ctx, cfg, newGitHub(os.Getenv("GITHUB_TOKEN")))
	cancel()
	if err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, cfg config, gh *gitHub) error {
	if cfg.Fork == "" {
		return fmt.Errorf("no fork repository: set -fork or GITHUB_REPOSITORY")
	}
	seen, err := readAcknowledged(cfg.Acknowledged)
	if err != nil {
		return err
	}
	issues, err := gh.watchIssues(ctx, cfg.Fork)
	if err != nil {
		return err
	}
	for _, issue := range issues {
		for _, key := range markerKeys(issue.Text) {
			seen[key] = true
		}
	}

	items, err := collect(ctx, cfg, gh)
	if err != nil {
		return err
	}
	unseen := filterUnseen(items, seen)
	log.Printf("%d items upstream, %d not seen before", len(items), len(unseen))
	if len(unseen) == 0 {
		return nil
	}

	return publish(ctx, cfg, gh, issues, unseen)
}

// publish adds unseen to the open upstream-watch issue, or opens one, or with
// -dry-run prints the report.
func publish(ctx context.Context, cfg config, gh *gitHub, issues []watchIssue, unseen []item) error {
	body := report(unseen, cfg.Notify)
	if cfg.DryRun {
		fmt.Println(body)
		return nil
	}
	if open := openIssue(issues); open != nil {
		log.Printf("commenting on #%d", open.Number)
		return gh.comment(ctx, cfg.Fork, open.Number, body)
	}
	title := fmt.Sprintf("Upstream watch: %d new item(s) to review", len(unseen))
	log.Printf("opening %q", title)
	return gh.openIssue(ctx, cfg.Fork, title, body, cfg.Notify)
}

// collect gathers every item upstream, seen or not.
func collect(ctx context.Context, cfg config, gh *gitHub) ([]item, error) {
	var items []item
	vulns, err := vulnItems(ctx, gh.http, cfg.Modules)
	if err != nil {
		return nil, err
	}
	items = append(items, vulns...)
	repo, err := repoItems(ctx, gh, cfg.Upstream)
	if err != nil {
		return nil, err
	}
	return append(items, repo...), nil
}

// readAcknowledged reads one key per line, ignoring blank lines and lines
// starting with #.
func readAcknowledged(path string) (map[string]bool, error) {
	f, err := os.Open(path) //nolint:gosec // the path is the -acknowledged flag, set by the workflow
	if err != nil {
		return nil, fmt.Errorf("reading acknowledged keys: %w", err)
	}
	defer func() { _ = f.Close() }()

	seen := map[string]bool{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			seen[strings.Fields(line)[0]] = true
		}
	}
	return seen, scanner.Err()
}
