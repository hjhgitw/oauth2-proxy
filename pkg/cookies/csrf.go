package cookies

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
	"github.com/vmihailenco/msgpack/v4"
)

var now = time.Now

// CSRF manages various nonces stored in the CSRF cookie during the initial
// authentication flows.
type CSRF interface {
	HashOAuthState() string
	HashOIDCNonce() string
	CheckOAuthState(string) bool
	CheckOIDCNonce(string) bool

	SetSessionNonce(s *sessions.SessionState)

	SetCookie(http.ResponseWriter, *http.Request) (*http.Cookie, error)
	ClearCookie(http.ResponseWriter, *http.Request)
}

type csrf struct {
	// OAuthState holds the OAuth2 state parameter's nonce component set in the
	// initial authentication request and mirrored back in the callback
	// redirect from the IdP for CSRF protection.
	OAuthState []byte `msgpack:"s,omitempty"`

	// OIDCNonce holds the OIDC nonce parameter used in the initial authentication
	// and then set in all subsequent OIDC ID Tokens as the nonce claim. This
	// is used to mitigate replay attacks.
	OIDCNonce []byte `msgpack:"n,omitempty"`

	cookieOpts *options.Cookie
}

// NewCSRF creates a CSRF with random nonces
func NewCSRF(opts *options.Cookie) (CSRF, error) {
	state, err := encryption.Nonce()
	if err != nil {
		return nil, err
	}
	nonce, err := encryption.Nonce()
	if err != nil {
		return nil, err
	}

	return &csrf{
		OAuthState: state,
		OIDCNonce:  nonce,

		cookieOpts: opts,
	}, nil
}

// LoadCSRFCookie loads a CSRF object from a request's CSRF cookie
func LoadCSRFCookie(req *http.Request, opts *options.Cookie) (CSRF, error) {
	cookie, err := req.Cookie(csrfCookieName(opts))
	if err != nil {
		return nil, err
	}

	return decodeCSRFCookie(cookie, opts)
}

// HashOAuthState returns the hash of the OAuth state nonce
func (c csrf) HashOAuthState() string {
	return encryption.HashNonce(c.OAuthState)
}

// HashOIDCNonce returns the hash of the OIDC nonce
func (c csrf) HashOIDCNonce() string {
	return encryption.HashNonce(c.OIDCNonce)
}

// CheckOAuthState compares the OAuth state nonce against a potential
// hash of it
func (c csrf) CheckOAuthState(hashed string) bool {
	return encryption.CheckNonce(c.OAuthState, hashed)
}

// CheckOIDCNonce compares the OIDC nonce against a potential hash of it
func (c csrf) CheckOIDCNonce(hashed string) bool {
	return encryption.CheckNonce(c.OIDCNonce, hashed)
}

// SetSessionNonce sets the OIDCNonce on a SessionState
func (c csrf) SetSessionNonce(s *sessions.SessionState) {
	s.Nonce = c.OIDCNonce
}

// SetCookie encodes the CSRF to a signed cookie and sets it on the ResponseWriter
func (c csrf) SetCookie(rw http.ResponseWriter, req *http.Request) (*http.Cookie, error) {
	encoded, err := c.encodeCookie()
	if err != nil {
		return nil, err
	}

	cookie := MakeCookieFromOptions(
		req,
		c.cookieName(),
		encoded,
		c.cookieOpts,
		c.cookieOpts.Expire,
		now(),
	)
	http.SetCookie(rw, cookie)

	return cookie, nil
}

// ClearCookie removes the CSRF cookie
func (c csrf) ClearCookie(rw http.ResponseWriter, req *http.Request) {
	http.SetCookie(rw, MakeCookieFromOptions(
		req,
		c.cookieName(),
		"",
		c.cookieOpts,
		time.Hour*-1,
		now(),
	))
}

// encodeCookie MessagePack encodes and encrypts the CSRF and then creates a
// signed cookie value
func (c csrf) encodeCookie() (string, error) {
	packed, err := msgpack.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("error marshalling CSRF to msgpack: %v", err)
	}

	encrypted, err := encrypt(packed, c.cookieOpts)
	if err != nil {
		return "", err
	}

	return encryption.SignedValue(c.cookieOpts.Secret, c.cookieName(), encrypted, now())
}

// decodeCSRFCookie validates the signature then decrypts and decodes a CSRF
// cookie into a CSRF struct
func decodeCSRFCookie(cookie *http.Cookie, opts *options.Cookie) (*csrf, error) {
	val, _, ok := encryption.Validate(cookie, opts.Secret, opts.Expire)
	if !ok {
		return nil, errors.New("CSRF cookie failed validation")
	}

	decrypted, err := decrypt(val, opts)
	if err != nil {
		return nil, err
	}

	// Valid cookie, Unmarshal the CSRF
	csrf := &csrf{cookieOpts: opts}
	err = msgpack.Unmarshal(decrypted, csrf)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling data to CSRF: %v", err)
	}

	return csrf, nil
}

// cookieName returns the CSRF cookie's name derived from the base
// session cookie name
func (c csrf) cookieName() string {
	return csrfCookieName(c.cookieOpts)
}

func csrfCookieName(opts *options.Cookie) string {
	return fmt.Sprintf("%v_csrf", opts.Name)
}

func encrypt(data []byte, opts *options.Cookie) ([]byte, error) {
	cipher, err := makeCipher(opts)
	if err != nil {
		return nil, err
	}
	return cipher.Encrypt(data)
}

func decrypt(data []byte, opts *options.Cookie) ([]byte, error) {
	cipher, err := makeCipher(opts)
	if err != nil {
		return nil, err
	}
	return cipher.Decrypt(data)
}

func makeCipher(opts *options.Cookie) (encryption.Cipher, error) {
	return encryption.NewCFBCipher([]byte(opts.Secret))
}
