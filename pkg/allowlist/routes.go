package allowlist

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// compiledRegex is an uncompiled => compiled regex mapping
// This is used in lieu of an array for deduplication
type compiledRegexes map[string]*regexp.Regexp

// Routes holds global & per-method path regexes that would trigger a request
// skipping authentication
type Routes struct {
	global  compiledRegexes
	methods map[string]compiledRegexes
}

// NewRoutes creates a Routes with empty Global & Methods fields
func NewRoutes() *Routes {
	return &Routes{
		global:  compiledRegexes{},
		methods: map[string]compiledRegexes{},
	}
}

// AddGlobalRegex compiles a path regex string and adds it to the global list
// of paths to trust
func (r *Routes) AddGlobalRegex(pathRegex string) error {
	if _, ok := r.global[pathRegex]; ok {
		return nil
	}
	compiled, err := regexp.Compile(pathRegex)
	if err != nil {
		return fmt.Errorf("error compiling regex /%s/: %v", pathRegex, err)
	}
	r.global[pathRegex] = compiled
	return nil
}

// AddMethodRegex compiles a path regex string and adds it to the list of
// paths to trust for the given method (GET, POST, PUT, etc)
func (r *Routes) AddMethodRegex(method string, pathRegex string) error {
	if _, ok := r.methods[method]; ok {
		if _, ok = r.methods[method][pathRegex]; ok {
			return nil
		}
	}
	compiled, err := regexp.Compile(pathRegex)
	if err != nil {
		return fmt.Errorf("error compiling regex /%s/: %v", pathRegex, err)
	}
	upperMethod := strings.ToUpper(method)
	if _, ok := r.methods[upperMethod]; !ok {
		r.methods[upperMethod] = compiledRegexes{}
	}
	r.methods[upperMethod][pathRegex] = compiled
	return nil
}

// IsTrusted processes a *http.Request against our trusted routes and
// determines if the request is trusted
func (r *Routes) IsTrusted(req *http.Request) bool {
	path := req.URL.Path
	for _, allowedPath := range r.global {
		if allowedPath.MatchString(path) {
			return true
		}
	}

	if allowedPaths, ok := r.methods[req.Method]; ok {
		for _, allowedPath := range allowedPaths {
			if allowedPath.MatchString(path) {
				return true
			}
		}
	}
	return false
}

// LogMessages creates messages for each trusted route for logging purposes
func (r *Routes) LogMessages() []string {
	logs := []string{}
	for strRegex := range r.global {
		logs = append(logs, fmt.Sprintf(
			"Skipping auth for allowlisted route: Method => ALL, Path Regex => %q", strRegex))
	}
	for method, regexes := range r.methods {
		for strRegex := range regexes {
			logs = append(logs, fmt.Sprintf(
				"Skipping auth for allowlisted route: Method => %s, Path Regex => %q", method, strRegex))
		}
	}
	return logs
}
