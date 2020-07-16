package allowlist

import "net/http"

// Allowlist is an interface for determining trusted requests that can
// skip authentication.
type Allowlist interface {
	IsTrusted(req *http.Request) bool
	LogMessages() []string
}
