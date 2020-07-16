package allowlist

import (
	"fmt"
	"net/http"

	ipapi "github.com/oauth2-proxy/oauth2-proxy/pkg/apis/ip"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/ip"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
)

// IPs holds *ip.NetSet representing IP/CIDRs we trust to skip authentication
type IPs struct {
	parser     ipapi.RealClientIPParser
	rawIPs     []string
	trustedIPs *ip.NetSet
}

// NewIPs creates a new IPs
func NewIPs(parser ipapi.RealClientIPParser) *IPs {
	return &IPs{
		parser:     parser,
		rawIPs:     []string{},
		trustedIPs: ip.NewNetSet(),
	}
}

// AddTrustedIP adds an IP/CIDR string to the trust list
func (i *IPs) AddTrustedIP(trustedIP string) error {
	if ipNet := ip.ParseIPNet(trustedIP); ipNet != nil {
		i.trustedIPs.AddIPNet(*ipNet)
		i.rawIPs = append(i.rawIPs, trustedIP)
		return nil
	}
	return fmt.Errorf("could not parse IP network (%s)", trustedIP)
}

// IsTrusted processes a *http.Request against our trusted IP/CIDRs and
// determines if the request is trusted
func (i *IPs) IsTrusted(req *http.Request) bool {
	if i.trustedIPs == nil {
		return false
	}

	remoteAddr, err := ip.GetClientIP(i.parser, req)
	if err != nil {
		logger.Printf("Error obtaining real IP for trusted IP list: %v", err)
		// Possibly spoofed X-Real-IP header
		return false
	}

	if remoteAddr == nil {
		return false
	}

	return i.trustedIPs.Has(remoteAddr)
}

// LogMessages creates messages for each trusted route for logging purposes
func (i *IPs) LogMessages() []string {
	logs := []string{}
	for _, cidr := range i.rawIPs {
		logs = append(logs, fmt.Sprintf(
			"Skipping auth for allowlisted IP/CIDR range: %s", cidr))
	}
	return logs
}
