package index

import (
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/authorization"
)

const (
	Get     = "GET"
	Post    = "POST"
	Put     = "PUT"
	Delete  = "DELETE"
	Head    = "HEAD"
	Options = "OPTIONS"
	Trace   = "TRACE"
	Patch   = "PATCH"
	Connect = "CONNECT"
)

var HTTPMethods = [...]string{Get, Post, Put, Delete, Head, Options, Trace, Patch, Connect}

// MethodsIndex indexes authorization.Rules by the Methods field
type MethodsIndex struct {
	methods map[string][]*authorization.Rule

	// Tracks index matches for index priority
	hits int
}

// NewMethodsIndex creates an index for the listed HTTPMethods
func NewMethodsIndex() *MethodsIndex {
	methods := make(map[string][]*authorization.Rule)
	for _, method := range HTTPMethods {
		methods[method] = nil
	}
	return &MethodsIndex{
		methods: methods,
		hits:    0,
	}
}

// Name provides an identifier for this index
func (i *MethodsIndex) Name() string {
	return "Methods"
}

// Hits returns how many times this index has matched a http.Request
func (i *MethodsIndex) Hits() int {
	return i.hits
}

// IndexRule indexes the authorization.Rule by its Methods
func (i *MethodsIndex) IndexRule(rule *authorization.Rule) bool {
	if rule.Methods == nil {
		return false
	}
	for method := range rule.Methods {
		for _, valid := range HTTPMethods {
			if method == valid {
				i.methods[method] = append(i.methods[method], rule)
			}
		}
	}
	return true
}

// MatchRules returns a list of authorization.Rules that fit the http.Request
func (i *MethodsIndex) MatchRules(req *http.Request) []*authorization.Rule {
	rules := i.methods[req.Method]
	if rules != nil {
		i.hits++
	}
	return rules
}
