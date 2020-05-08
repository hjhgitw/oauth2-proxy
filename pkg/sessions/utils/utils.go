package utils

import (
	"encoding/base64"
	"errors"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/encryption"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/sessions/envelope"
)

// CookieForSession serializes a session state for storage in a cookie
func CookieForSession(s *sessions.SessionState, c *encryption.Cipher, compressed bool) ([]byte, error) {
	// if no cipher, don't include tokens
	minimal := c == nil
	data, err := s.EncodeSessionState(compressed, minimal)
	if err != nil {
		return []byte{}, err
	}

	encType := envelope.NoEncryption
	if c != nil {
		encType = envelope.CFBEncryption
		// Use AES-CFB on encrypted data in cookies since the same cookie secret is reused
		// AES-GCM is weak to a repeat of the IV Nonce + Secret
		// The AES-CFB lack of authentication is mitigated by SHA signing the cookie.
		data, err = c.EncryptCFB(data)
		if err != nil {
			return []byte{}, err
		}
	}

	se := &envelope.StoreEnvelope{
		Type:       envelope.CookieType,
		Encryption: encType,
		Compressed: compressed,
		Data:       data,
	}
	value, err := se.Marshal()
	if err != nil {
		return []byte{}, err
	}
	return value, nil
}

// SessionFromCookie deserializes a session from a cookie value
func SessionFromCookie(v []byte, c *encryption.Cipher) (*sessions.SessionState, error) {
	var (
		se  *envelope.StoreEnvelope
		ss  *sessions.SessionState
		err error
	)

	se, err = envelope.UnmarshalStoreEnvelope(v)
	if err != nil {
		// If we fail, assume an uncompressed cookie was passed
		return sessions.LegacyV5DecodeSessionState(string(v), c)
	}

	if se.Type != envelope.CookieType {
		return nil, errors.New("invalid session store type")
	}

	// Future: allows differing encryption algorithms
	if se.Encryption == envelope.CFBEncryption {
		se.Data, err = c.DecryptCFB(se.Data)
		if err != nil {
			return nil, err
		}
	}

	ss, err = sessions.DecodeSessionState(se.Data, se.Compressed)
	if err != nil {
		return nil, err
	}
	return ss, nil
}

// SecretBytes attempts to base64 decode the secret, if that fails it treats the secret as binary
func SecretBytes(secret string) []byte {
	b, err := base64.URLEncoding.DecodeString(addPadding(secret))
	if err == nil {
		return []byte(addPadding(string(b)))
	}
	return []byte(secret)
}

func addPadding(secret string) string {
	padding := len(secret) % 4
	switch padding {
	case 1:
		return secret + "==="
	case 2:
		return secret + "=="
	case 3:
		return secret + "="
	default:
		return secret
	}
}
