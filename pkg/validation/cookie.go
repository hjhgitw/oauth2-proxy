package validation

import (
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/encryption"
)

func validateCookie(o options.Cookie) []string {
	msgs := validateCookieSecret(o.Secret)

	if o.Refresh >= o.Expire {
		msgs = append(msgs, fmt.Sprintf(
			"cookie_refresh (%q) must be less than cookie_expire (%q)",
			o.Refresh.String(),
			o.Expire.String()))
	}

	switch o.SameSite {
	case "", "none", "lax", "strict":
	default:
		msgs = append(msgs, fmt.Sprintf("cookie_samesite (%q) must be one of ['', 'lax', 'strict', 'none']", o.SameSite))
	}

	// Sort cookie domains by length, so that we try longer (and more specific) domains first
	sort.Slice(o.Domains, func(i, j int) bool {
		return len(o.Domains[i]) > len(o.Domains[j])
	})

	msgs = append(msgs, validateCookieName(o.Name)...)
	return msgs
}

func validateCookieName(name string) []string {
	msgs := []string{}

	cookie := &http.Cookie{Name: name}
	if cookie.String() == "" {
		msgs = append(msgs, fmt.Sprintf("invalid cookie name: %q", name))
	}

	if len(name) > 256 {
		msgs = append(msgs, fmt.Sprintf("cookie name should be under 256 characters: cookie name is %d characters", len(name)))
	}
	return msgs
}

func validateCookieSecret(secret string) []string {
	if secret == "" {
		return []string{"missing setting: cookie-secret"}
	}

	secretBytes := encryption.SecretBytes(secret)
	// Check if the secret is a valid length
	switch len(secretBytes) {
	case 16, 24, 32:
		// Valid secret size found
		return []string{}
	}
	// Invalid secret size found, return a message
	return []string{fmt.Sprintf(
		"cookie_secret must be 16, 24, or 32 bytes to create an AES cipher, but is %d bytes",
		len(secretBytes)),
	}
}

func validateCookieMinimal(o *options.Options) []string {
	if !o.Cookie.Minimal {
		return []string{}
	}

	msgs := []string{}
	if o.PassAuthorization {
		msgs = append(msgs,
			"pass_authorization_header requires oauth tokens in sessions. cookie_minimal cannot be set")
	}
	if o.SetAuthorization {
		msgs = append(msgs,
			"set_authorization_header requires oauth tokens in sessions. cookie_minimal cannot be set")
	}
	if o.PassAccessToken {
		msgs = append(msgs,
			"pass_access_token requires oauth tokens in sessions. cookie_minimal cannot be set")
	}
	if o.Cookie.Refresh != time.Duration(0) {
		msgs = append(msgs,
			"cookie_refresh > 0 requires oauth tokens in sessions. cookie_minimal cannot be set")
	}
	return msgs
}
