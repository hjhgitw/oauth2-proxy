package index

import (
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/authorization"
)

// PathIndex attempts to index a Path regex as if it were a raw string
type PathIndex struct {
	paths map[string][]*authorization.Rule

	// Tracks index matches for index priority
	hits int
}

// NewPathIndex makes an index from a path regex.
// It assumes the regex has no complexity and is essentially a string
func NewPathIndex() *PathIndex {
	return &PathIndex{
		paths: make(map[string][]*authorization.Rule),
		hits:  0,
	}
}

// Name provides an identifier for this index
func (i *PathIndex) Name() string {
	return "Path"
}

// Hits returns how many times this index has matched a http.Request
func (i *PathIndex) Hits() int {
	return i.hits
}

// IndexRule indexes the authorization.Rule by Path
func (i *PathIndex) IndexRule(rule *authorization.Rule) bool {
	if rule.Path == nil {
		return false
	}

	rawRegex := rule.Path.Raw
	start := 0
	end := len(rawRegex)
	if rawRegex[:1] == "^" {
		start = 1
	}
	if rawRegex[end-1:] == "$" {
		end = end - 1
	}
	indexPath := rawRegex[start:end]
	i.paths[indexPath] = append(i.paths[indexPath], rule)

	return true
}

// MatchRules returns a list of authorization.Rules that fit the http.Request
func (i *PathIndex) MatchRules(req *http.Request) []*authorization.Rule {
	if rules, ok := i.paths[req.URL.Path]; ok {
		i.hits++
		return rules
	}
	return nil
}
