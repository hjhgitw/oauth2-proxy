package sessions

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/pierrec/lz4"
	"github.com/vmihailenco/msgpack/v4"
	"io"
	"io/ioutil"
	"strconv"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/encryption"
)

// SessionState is used to store information about the currently authenticated user session
// MessagePack naming aligned to match with internal JWT claims for compression synergy
type SessionState struct {
	AccessToken       string    `json:",omitempty" msgpack:"at,omitempty"`
	IDToken           string    `json:",omitempty" msgpack:"it,omitempty"`
	CreatedAt         time.Time `json:"-" msgpack:"-"`
	ExpiresOn         time.Time `json:"-" msgpack:"-"`
	RefreshToken      string    `json:",omitempty" msgpack:"rt,omitempty"`
	Email             string    `json:",omitempty" msgpack:"e,omitempty"`
	User              string    `json:",omitempty" msgpack:"u,omitempty"`
	PreferredUsername string    `json:",omitempty" msgpack:"pu,omitempty"`
}

// SessionStateEncoded is used to encode SessionState into JSON/MessagePack
// without exposing time.Time zero value
type SessionStateEncoded struct {
	*SessionState
	CreatedAt *time.Time `json:",omitempty" msgpack:"ca,omitempty"`
	ExpiresOn *time.Time `json:",omitempty" msgpack:"eo,omitempty"`
}

// IsExpired checks whether the session has expired
func (s *SessionState) IsExpired() bool {
	if !s.ExpiresOn.IsZero() && s.ExpiresOn.Before(time.Now()) {
		return true
	}
	return false
}

// Age returns the age of a session
func (s *SessionState) Age() time.Duration {
	if !s.CreatedAt.IsZero() {
		return time.Now().Truncate(time.Second).Sub(s.CreatedAt)
	}
	return 0
}

// String constructs a summary of the session state
func (s *SessionState) String() string {
	o := fmt.Sprintf("Session{email:%s user:%s PreferredUsername:%s", s.Email, s.User, s.PreferredUsername)
	if s.AccessToken != "" {
		o += " token:true"
	}
	if s.IDToken != "" {
		o += " id_token:true"
	}
	if !s.CreatedAt.IsZero() {
		o += fmt.Sprintf(" created:%s", s.CreatedAt)
	}
	if !s.ExpiresOn.IsZero() {
		o += fmt.Sprintf(" expires:%s", s.ExpiresOn)
	}
	if s.RefreshToken != "" {
		o += " refresh_token:true"
	}
	return o + "}"
}

// EncodeSessionState returns an lz4 compression (optional) of a MessagePack encoded session
// Encryption & Base64 encoding are delegated to downstream consumers of this method.
func (s *SessionState) EncodeSessionState(compress bool, minimal bool) ([]byte, error) {
	var (
		ss  SessionState
		err error

		// LZ4 & MessagePack
		packed []byte
		reader *bytes.Reader
		buf    *bytes.Buffer
		zw     *lz4.Writer
	)

	ss = *s

	// Embed SessionState, Decoded Tokens and Expires pointers into SessionStateCompressed
	sse := &SessionStateEncoded{SessionState: &ss}
	if !ss.CreatedAt.IsZero() {
		sse.CreatedAt = &ss.CreatedAt
	}
	if !ss.ExpiresOn.IsZero() {
		sse.ExpiresOn = &ss.ExpiresOn
	}
	if minimal {
		sse.AccessToken = ""
		sse.IDToken = ""
		sse.RefreshToken = ""
	}

	//Marshal & Compress the SessionStateCompressed
	packed, err = msgpack.Marshal(sse)
	if err != nil {
		return []byte{}, err
	}

	if !compress {
		return packed, nil
	}

	// The Compress:Decompress ratio is 1:Many. LZ4 gives fastest decompress speeds
	buf = new(bytes.Buffer)
	zw = lz4.NewWriter(nil)
	zw.Header = lz4.Header{
		BlockMaxSize:     65536,
		CompressionLevel: 0,
	}
	zw.Reset(buf)

	reader = bytes.NewReader(packed)
	_, err = io.Copy(zw, reader)
	if err != nil {
		return []byte{}, err
	}
	_ = zw.Close()

	return ioutil.ReadAll(buf)
}

// DecodeSessionState decodes a LZ4 compressed MessagePack into a Session State
func DecodeSessionState(data []byte, compressed bool) (*SessionState, error) {
	var (
		sse SessionStateEncoded
		ss  *SessionState
		err error

		// LZ4 & MessagePack
		buf    *bytes.Buffer
		reader *bytes.Reader
		zr     *lz4.Reader
		packed []byte
	)

	packed = data
	if compressed {
		reader = bytes.NewReader(data)
		buf = new(bytes.Buffer)
		zr = lz4.NewReader(nil)
		zr.Reset(reader)
		_, err = io.Copy(buf, zr)
		if err != nil {
			return nil, err
		}

		packed, err = ioutil.ReadAll(buf)
		if err != nil {
			return nil, err
		}
	}

	err = msgpack.Unmarshal(packed, &sse)
	if err != nil {
		return nil, err
	}
	if sse.SessionState == nil {
		return nil, fmt.Errorf("failed to decode the session state")
	}

	ss = sse.SessionState
	if sse.CreatedAt != nil {
		ss.CreatedAt = *sse.CreatedAt
	}
	if sse.ExpiresOn != nil {
		ss.ExpiresOn = *sse.ExpiresOn
	}

	// Holdover behavior from Legacy decode
	// NOTE: this makes decode NOT a 1:1 reversal of Encode
	// TODO: Is this the best place for this logic?
	if ss.User == "" {
		ss.User = ss.Email
	}
	return ss, nil
}

// legacyDecodeSessionStatePlain decodes older plain session state string
func legacyDecodeSessionStatePlain(v string) (*SessionState, error) {
	chunks := strings.Split(v, " ")
	if len(chunks) != 2 {
		return nil, fmt.Errorf("invalid session state (legacy: expected 2 chunks for user/email got %d)", len(chunks))
	}

	user := strings.TrimPrefix(chunks[1], "user:")
	email := strings.TrimPrefix(chunks[0], "email:")

	return &SessionState{User: user, Email: email}, nil
}

// legacyDecodeSessionState attempts to decode the session state string
// generated by v3.1.0 or older
func legacyV3DecodeSessionState(v string, c *encryption.Cipher) (*SessionState, error) {
	chunks := strings.Split(v, "|")

	if c == nil {
		if len(chunks) != 1 {
			return nil, fmt.Errorf("invalid session state (legacy: expected 1 chunk for plain got %d)", len(chunks))
		}
		return legacyDecodeSessionStatePlain(chunks[0])
	}

	if len(chunks) != 4 && len(chunks) != 5 {
		return nil, fmt.Errorf("invalid session state (legacy: expected 4 or 5 chunks for full got %d)", len(chunks))
	}

	i := 0
	ss, err := legacyDecodeSessionStatePlain(chunks[i])
	if err != nil {
		return nil, err
	}

	i++
	ss.AccessToken = chunks[i]

	if len(chunks) == 5 {
		// SessionState with IDToken in v3.1.0
		i++
		ss.IDToken = chunks[i]
	}

	i++
	ts, err := strconv.Atoi(chunks[i])
	if err != nil {
		return nil, fmt.Errorf("invalid session state (legacy: wrong expiration time: %s)", err)
	}
	ss.ExpiresOn = time.Unix(int64(ts), 0)

	i++
	ss.RefreshToken = chunks[i]

	return ss, nil
}

// DecodeSessionState decodes the session cookie string into a SessionState
func LegacyV5DecodeSessionState(v string, c *encryption.Cipher) (*SessionState, error) {
	var ssj SessionStateEncoded
	var ss *SessionState
	err := json.Unmarshal([]byte(v), &ssj)
	if err == nil && ssj.SessionState != nil {
		// Extract SessionState and CreatedAt,ExpiresOn value from SessionStateEncoded
		ss = ssj.SessionState
		if ssj.CreatedAt != nil {
			ss.CreatedAt = *ssj.CreatedAt
		}
		if ssj.ExpiresOn != nil {
			ss.ExpiresOn = *ssj.ExpiresOn
		}
	} else {
		// Try to decode a legacy string when json.Unmarshal failed
		ss, err = legacyV3DecodeSessionState(v, c)
		if err != nil {
			return nil, err
		}
	}
	if c == nil {
		// Load only Email and User when cipher is unavailable
		ss = &SessionState{
			Email:             ss.Email,
			User:              ss.User,
			PreferredUsername: ss.PreferredUsername,
		}
	} else {
		// Backward compatibility with using unencrypted Email
		if ss.Email != "" {
			decryptedEmail, errEmail := c.LegacyDecrypt(ss.Email)
			if errEmail == nil {
				ss.Email = decryptedEmail
			}
		}
		// Backward compatibility with using unencrypted User
		if ss.User != "" {
			decryptedUser, errUser := c.LegacyDecrypt(ss.User)
			if errUser == nil {
				ss.User = decryptedUser
			}
		}
		if ss.PreferredUsername != "" {
			ss.PreferredUsername, err = c.LegacyDecrypt(ss.PreferredUsername)
			if err != nil {
				return nil, err
			}
		}
		if ss.AccessToken != "" {
			ss.AccessToken, err = c.LegacyDecrypt(ss.AccessToken)
			if err != nil {
				return nil, err
			}
		}
		if ss.IDToken != "" {
			ss.IDToken, err = c.LegacyDecrypt(ss.IDToken)
			if err != nil {
				return nil, err
			}
		}
		if ss.RefreshToken != "" {
			ss.RefreshToken, err = c.LegacyDecrypt(ss.RefreshToken)
			if err != nil {
				return nil, err
			}
		}
	}
	if ss.User == "" {
		ss.User = ss.Email
	}
	return ss, nil
}
