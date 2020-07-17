package validation

import (
	"fmt"
	"os"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/authorization"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/authorization/engine"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/authorization/index"
)

func validateAuthorization(o *options.Options) []string {
	msgs := []string{}

	re := engine.NewRulesEngine(o.GetRealClientIPParser())
	msgs = append(msgs, validateRoutes(&o.Authorization, re)...)
	msgs = append(msgs, validateRegexes(&o.Authorization, re)...)
	msgs = append(msgs, validatePreflight(&o.Authorization, re)...)
	msgs = append(msgs, validateTrustedIPs(&o.Authorization, re)...)

	if len(o.Authorization.TrustedIPs) > 0 && o.ReverseProxy {
		_, err := fmt.Fprintln(os.Stderr, "WARNING: mixing --trusted-ip with --reverse-proxy is a potential security vulnerability. An attacker can inject a trusted IP into an X-Real-IP or X-Forwarded-For header if they aren't properly protected outside of oauth2-proxy")
		if err != nil {
			panic(err)
		}
	}

	o.Authorization.SetRulesEngine(re)
	return msgs
}

// validateRoutes validates method=path routes passed with options.Authorization.SkipAuthRoutes
func validateRoutes(o *options.Authorization, e *engine.RulesEngine) []string {
	msgs := []string{}
	for i, route := range o.SkipAuthRoutes {
		parts := strings.Split(route, "=")
		if len(parts) == 1 {
			rule, err := authorization.NewRule(
				fmt.Sprintf("route-%d", i),
				authorization.Allow,
				parts[0],
				nil,
				nil)
			if err != nil {
				msgs = append(msgs, fmt.Sprintf("%s", err))
			} else {
				e.AddRule(rule)
			}
		} else {
			method := parts[0]
			regex := strings.Join(parts[1:], "=")
			rule, err := authorization.NewRule(
				fmt.Sprintf("route-%d", i),
				authorization.Allow,
				regex,
				[]string{method},
				nil)
			if err != nil {
				msgs = append(msgs, fmt.Sprintf("%s", err))
			} else {
				e.AddRule(rule)
			}
		}
	}
	return msgs
}

// validateRegex validates regex paths passed with options.Allowlist.SkipAuthRegex
func validateRegexes(o *options.Authorization, e *engine.RulesEngine) []string {
	msgs := []string{}
	for i, regex := range o.SkipAuthRegex {
		rule, err := authorization.NewRule(
			fmt.Sprintf("regex-%d", i),
			authorization.Allow,
			regex,
			nil,
			nil)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("%s", err))
		} else {
			e.AddRule(rule)
		}
	}
	return msgs
}

// validatePreflight converts the options.Authorization.SkipAuthPreflight into an
// OPTIONS=.* route rule
func validatePreflight(o *options.Authorization, e *engine.RulesEngine) []string {
	msgs := []string{}
	if o.SkipAuthPreflight {
		rule, err := authorization.NewRule(
			"preflight",
			authorization.Allow,
			"",
			[]string{index.Options},
			nil)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("%s", err))
		} else {
			e.AddRule(rule)
		}
	}
	return msgs
}

// validateTrustedIPs validates IP/CIDRs for IP based allowlists
func validateTrustedIPs(o *options.Authorization, e *engine.RulesEngine) []string {
	rule, err := authorization.NewRule(
		"trustedIP",
		authorization.Allow,
		"",
		nil,
		o.TrustedIPs)
	if err != nil {
		return []string{fmt.Sprintf("%s", err)}
	}
	e.AddRule(rule)
	return []string{}
}
