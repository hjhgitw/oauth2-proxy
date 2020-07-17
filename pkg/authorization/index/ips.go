package index

import (
	"net/http"

	ipapi "github.com/oauth2-proxy/oauth2-proxy/pkg/apis/ip"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/authorization"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/ip"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
)

// IPsIndex holds authorization.Rules for a set of trusted IPs
type IPsIndex struct {
	Rules []*authorization.Rule

	parser     ipapi.RealClientIPParser
	trustedIPs *ip.NetSet

	// Tracks index matches for index priority
	hits int
}

// NewIPsIndex creates a authorization.Rule index out of its IPs field
func NewIPsIndex(parser ipapi.RealClientIPParser) *IPsIndex {
	return &IPsIndex{
		parser:     parser,
		trustedIPs: ip.NewNetSet(),
		hits:       0,
	}
}

// Name provides an identifier for this index
func (i *IPsIndex) Name() string {
	return "Network"
}

// Hits returns how many times this index has matched a http.Request
func (i *IPsIndex) Hits() int {
	return i.hits
}

// IndexRule indexes the authorization.Rule by the net.IPNets in its IPs
func (i *IPsIndex) IndexRule(rule *authorization.Rule) bool {
	if rule.IPs == nil {
		return false
	}
	i.Rules = append(i.Rules, rule)
	for _, ipNet := range rule.IPs.GetIPNets() {
		i.trustedIPs.AddIPNet(ipNet)
	}
	return true
}

// MatchRules returns a list of authorization.Rules that fit the http.Request
func (i *IPsIndex) MatchRules(req *http.Request) []*authorization.Rule {
	if i.trustedIPs == nil {
		return nil
	}

	remoteAddr, err := ip.GetClientIP(i.parser, req)
	if err != nil {
		logger.Printf("Error obtaining real IP for trusted IP list: %v", err)
		// Possibly spoofed X-Real-IP header
		return nil
	}

	if remoteAddr == nil {
		return nil
	}

	if i.trustedIPs.Has(remoteAddr) {
		i.hits++
		return i.Rules
	} else {
		return nil
	}
}
