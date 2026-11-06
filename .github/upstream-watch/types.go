package main

// The JSON this tool reads from vuln.go.dev and the GitHub REST API, and the
// JSON it sends to GitHub. Only the fields used are declared.

// vulnModuleJSON is one module's entry in https://vuln.go.dev/index/modules.json.
type vulnModuleJSON struct {
	Path  string `json:"path"`
	Vulns []struct {
		ID    string `json:"id"`
		Fixed string `json:"fixed"`
	} `json:"vulns"`
}

type tagJSON struct {
	Name string `json:"name"`
}

type commitJSON struct {
	SHA    string `json:"sha"`
	Commit struct {
		Message string `json:"message"`
	} `json:"commit"`
}

type pullJSON struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	Body   string `json:"body"`
	URL    string `json:"html_url"`
	User   struct {
		Login string `json:"login"`
	} `json:"user"`
}

type issueJSON struct {
	Number int    `json:"number"`
	State  string `json:"state"`
	Body   string `json:"body"`
}

// commentJSON is an issue comment, read and sent.
type commentJSON struct {
	Body string `json:"body"`
}

type newIssueJSON struct {
	Title     string   `json:"title"`
	Body      string   `json:"body"`
	Labels    []string `json:"labels"`
	Assignees []string `json:"assignees,omitempty"`
}

// apiResponse is every response body getJSON decodes.
type apiResponse interface {
	[]vulnModuleJSON | []tagJSON | []commitJSON | []pullJSON | []issueJSON | []commentJSON
}

// apiRequest is every request body ghPost sends.
type apiRequest interface {
	commentJSON | newIssueJSON
}
