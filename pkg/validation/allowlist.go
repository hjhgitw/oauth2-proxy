package validation

import (
	"fmt"
	"os"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/allowlist"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
)

// validateAllowlist validates both route & IP based allowlists and constructs
// the []allowlist.Allowlist of both
func validateAllowlist(o *options.Options) []string {
	msgs := []string{}

	routes := allowlist.NewRoutes()
	msgs = append(msgs, validateRoutes(&o.Allowlist, routes)...)
	msgs = append(msgs, validateRegexes(&o.Allowlist, routes)...)
	msgs = append(msgs, validatePreflight(&o.Allowlist, routes)...)

	ips := allowlist.NewIPs(o.GetRealClientIPParser())
	msgs = append(msgs, validateTrustedIPs(&o.Allowlist, ips)...)

	if len(o.Allowlist.TrustedIPs) > 0 && o.ReverseProxy {
		_, err := fmt.Fprintln(os.Stderr, "WARNING: mixing --trusted-ip with --reverse-proxy is a potential security vulnerability. An attacker can inject a trusted IP into an X-Real-IP or X-Forwarded-For header if they aren't properly protected outside of oauth2-proxy")
		if err != nil {
			panic(err)
		}
	}

	o.Allowlist.SetAllowlists([]allowlist.Allowlist{routes, ips})
	return msgs
}

// validateRoutes validates method=path routes passed with options.Allowlist.SkipAuthRoutes
func validateRoutes(o *options.Allowlist, r *allowlist.Routes) []string {
	msgs := []string{}
	for _, route := range o.SkipAuthRoutes {
		parts := strings.Split(route, "=")
		if len(parts) == 1 {
			err := r.AddGlobalRegex(parts[0])
			if err != nil {
				msgs = append(msgs, fmt.Sprintf("%s", err))
			}
		} else {
			method := parts[0]
			regex := strings.Join(parts[1:], "=")
			err := r.AddMethodRegex(method, regex)
			if err != nil {
				msgs = append(msgs, fmt.Sprintf("%s", err))
			}
		}
	}
	return msgs
}

// validateRegex validates regex paths passed with options.Allowlist.SkipAuthRegex
func validateRegexes(o *options.Allowlist, r *allowlist.Routes) []string {
	msgs := []string{}
	for _, regex := range o.SkipAuthRegex {
		err := r.AddGlobalRegex(regex)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("%s", err))
		}
	}
	return msgs
}

// validatePreflight converts the options.Allowlist.SkipAuthPreflight into an
// OPTIONS=.* route rule
func validatePreflight(o *options.Allowlist, r *allowlist.Routes) []string {
	msgs := []string{}
	if o.SkipAuthPreflight {
		err := r.AddMethodRegex("OPTIONS", ".*")
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("%s", err))
		}
	}
	return msgs
}

// validateTrustedIPs validates IP/CIDRs for IP based allowlists
func validateTrustedIPs(o *options.Allowlist, i *allowlist.IPs) []string {
	msgs := []string{}
	for _, trustedIP := range o.TrustedIPs {
		err := i.AddTrustedIP(trustedIP)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("%s", err))
		}
	}
	return msgs
}
