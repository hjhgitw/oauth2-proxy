package index

import (
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/authorization"
)

// Index handles indexing authorization.Rules for faster rule processing
type Index interface {
	Name() string
	Hits() int
	IndexRule(rule *authorization.Rule) bool
	MatchRules(req *http.Request) []*authorization.Rule
}
