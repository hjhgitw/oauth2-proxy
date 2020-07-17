package authorization

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	ipapi "github.com/oauth2-proxy/oauth2-proxy/pkg/apis/ip"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/ip"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
)

const (
	Allow = "ALLOW"
	Deny  = "DENY"
)

// PathRegex helps track the original & compiled path regex together
type PathRegex struct {
	Raw      string
	Compiled *regexp.Regexp
}

// Rule represents an authorization rule to be used for Allow & Deny policies
// on fields in a request
type Rule struct {
	// ID is a unique ID for the rule (used in RulesEngine memoization)
	ID string
	// Policy is either Allow or Deny
	Policy string
	// Path is a regex that will be tested against the req.URL.Path
	Path *PathRegex
	// Methods is list of HTTP methods. This group is an OR operation.
	Methods map[string]struct{}
	// IPS is a list of IPs or CIDRs. This group is an OR operation
	IPs *ip.NetSet

	// Priority management
	hits int
}

// NewRule creates a new authorization rule
// Use `nil` for any fields that aren't applicable to the rule
func NewRule(id string, policy string, path string, methods []string, ips []string) (*Rule, error) {
	if !(policy == Allow || policy == Deny) {
		return nil, fmt.Errorf("invalid policy type: %s", policy)
	}

	pathRegex, err := buildPathRegex(path)
	if err != nil {
		return nil, err
	}

	methodSet := buildMethodSet(methods)

	netSet, err := buildNetSet(ips)
	if err != nil {
		return nil, err
	}

	return &Rule{
		ID:      id,
		Policy:  policy,
		Path:    pathRegex,
		Methods: methodSet,
		IPs:     netSet,

		hits: 0,
	}, nil
}

// Hits tracks the number of times this rule passes a policy check
func (r *Rule) Hits() int {
	return r.hits
}

// Allow checks if a request passes all field checks for an Allow policy
func (r *Rule) Allow(req *http.Request, parser ipapi.RealClientIPParser) bool {
	if r.Policy == Allow && r.checkPath(req) && r.checkMethods(req) && r.checkIPs(req, parser) {
		r.hits++
		return true
	}
	return false
}

// Allow checks if a request passes all field checks for a Deny policy
func (r *Rule) Deny(req *http.Request, parser ipapi.RealClientIPParser) bool {
	if r.Policy == Deny && r.checkPath(req) && r.checkMethods(req) && r.checkIPs(req, parser) {
		r.hits++
		return true
	}
	return false
}

// buildPathRegex helps build the PathRegex from a raw path regex string
func buildPathRegex(path string) (*PathRegex, error) {
	if path == "" {
		return nil, nil
	}
	compiled, err := regexp.Compile(path)
	if err != nil {
		return nil, fmt.Errorf("error compiling regex /%s/: %v", path, err)
	}
	return &PathRegex{
		Raw:      path,
		Compiled: compiled,
	}, nil
}

// buildMethodSet takes a list of Methods and creates the Methods field set
func buildMethodSet(methods []string) map[string]struct{} {
	if methods == nil {
		return nil
	}
	ms := map[string]struct{}{}
	for _, method := range methods {
		ms[strings.ToUpper(method)] = struct{}{}
	}
	return ms
}

// buildNetSet takes trusted IPs and builds a unified ip.NetSet
func buildNetSet(ips []string) (*ip.NetSet, error) {
	if ips == nil {
		return nil, nil
	}

	ns := ip.NewNetSet()
	var failed []string
	failed = nil
	for _, trustedIP := range ips {
		if ipNet := ip.ParseIPNet(trustedIP); ipNet != nil {
			ns.AddIPNet(*ipNet)
		} else {
			failed = append(failed, trustedIP)
		}
	}
	if failed != nil {
		return nil, fmt.Errorf("could not parse trusted IP network(s): %s", strings.Join(failed, ", "))
	}
	return ns, nil
}

// checkPath does a regex check against the request path
func (r *Rule) checkPath(req *http.Request) bool {
	if r.Path == nil {
		return true
	}
	return r.Path.Compiled.MatchString(req.URL.Path)
}

// checkMethods does a set membership test of the request method
func (r *Rule) checkMethods(req *http.Request) bool {
	if r.Methods == nil {
		return true
	}
	if _, ok := r.Methods[req.Method]; ok {
		return true
	}
	return false
}

// checkIPs checks if the request remote IP is in the ip.NetSet
// This is reverse proxy aware if a ipapi.RealClientIPParser is passed
func (r *Rule) checkIPs(req *http.Request, parser ipapi.RealClientIPParser) bool {
	if r.IPs == nil {
		return true
	}

	remoteAddr, err := ip.GetClientIP(parser, req)
	if err != nil {
		logger.Printf("Error obtaining real IP for trusted IP list: %v", err)
		// Possibly spoofed X-Real-IP header
		return false
	}

	if remoteAddr == nil {
		return false
	}

	return r.IPs.Has(remoteAddr)
}
