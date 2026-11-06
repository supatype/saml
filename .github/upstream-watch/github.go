package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

const watchLabel = "upstream-watch"

// gitHub is a minimal GitHub REST client.
type gitHub struct {
	http  *http.Client
	api   string
	token string
}

func newGitHub(token string) *gitHub {
	return &gitHub{http: &http.Client{Timeout: 30 * time.Second}, api: "https://api.github.com", token: token}
}

// watchIssue is an upstream-watch issue with its body and comments joined.
type watchIssue struct {
	Number int
	Open   bool
	Text   string
}

// watchIssues returns every issue labelled upstream-watch, open or closed.
func (gh *gitHub) watchIssues(ctx context.Context, repo string) ([]watchIssue, error) {
	var issues []watchIssue
	for page := 1; ; page++ {
		path := fmt.Sprintf("/repos/%s/issues?labels=%s&state=all&per_page=100&page=%d", repo, watchLabel, page)
		batch, err := ghGet[[]issueJSON](ctx, gh, path)
		if err != nil {
			return nil, err
		}
		for _, b := range batch {
			text, err := gh.commentText(ctx, repo, b.Number)
			if err != nil {
				return nil, err
			}
			issues = append(issues, watchIssue{Number: b.Number, Open: b.State == "open", Text: b.Body + "\n" + text})
		}
		if len(batch) < 100 {
			return issues, nil
		}
	}
}

func (gh *gitHub) commentText(ctx context.Context, repo string, number int) (string, error) {
	var text bytes.Buffer
	for page := 1; ; page++ {
		path := fmt.Sprintf("/repos/%s/issues/%d/comments?per_page=100&page=%d", repo, number, page)
		comments, err := ghGet[[]commentJSON](ctx, gh, path)
		if err != nil {
			return "", err
		}
		for _, c := range comments {
			text.WriteString(c.Body)
			text.WriteString("\n")
		}
		if len(comments) < 100 {
			return text.String(), nil
		}
	}
}

// openIssue returns the lowest-numbered open issue, or nil.
func openIssue(issues []watchIssue) *watchIssue {
	var found *watchIssue
	for i := range issues {
		if issues[i].Open && (found == nil || issues[i].Number < found.Number) {
			found = &issues[i]
		}
	}
	return found
}

func (gh *gitHub) comment(ctx context.Context, repo string, number int, body string) error {
	path := "/repos/" + repo + "/issues/" + strconv.Itoa(number) + "/comments"
	return ghPost(ctx, gh, path, commentJSON{Body: body})
}

func (gh *gitHub) openIssue(ctx context.Context, repo, title, body, assignee string) error {
	issue := newIssueJSON{Title: title, Body: body, Labels: []string{watchLabel}}
	if assignee != "" {
		issue.Assignees = []string{assignee}
	}
	return ghPost(ctx, gh, "/repos/"+repo+"/issues", issue)
}

// ghGet fetches a GitHub API path and decodes its JSON body.
func ghGet[T apiResponse](ctx context.Context, gh *gitHub, path string) (T, error) {
	return getJSON[T](ctx, gh.http, gh.api+path, gh.token)
}

// ghPost sends payload to a GitHub API path as JSON.
func ghPost[T apiRequest](ctx context.Context, gh *gitHub, path string, payload T) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gh.api+path, bytes.NewReader(body)) //nolint:gosec // gh.api is api.github.com
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := do(gh.http, req, gh.token)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// getJSON fetches url and decodes its JSON body. token, when set, is
// sent as a GitHub bearer token.
func getJSON[T apiResponse](ctx context.Context, client *http.Client, url, token string) (T, error) {
	var out T
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) //nolint:gosec // api.github.com or vuln.go.dev
	if err != nil {
		return out, err
	}
	resp, err := do(client, req, token)
	if err != nil {
		return out, err
	}
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, fmt.Errorf("decoding %s: %w", url, err)
	}
	return out, nil
}

// do sends req and returns the response, or an error naming the status for
// anything other than 2xx.
func do(client *http.Client, req *http.Request, token string) (*http.Response, error) {
	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	// Every URL is api.github.com or vuln.go.dev, built from constants.
	resp, err := client.Do(req) //nolint:gosec // see above
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%s %s: %s: %s", req.Method, req.URL, resp.Status, msg)
	}
	return resp, nil
}
