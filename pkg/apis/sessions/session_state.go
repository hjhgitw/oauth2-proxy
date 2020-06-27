package sessions

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"time"
	"unicode/utf8"

	"github.com/pierrec/lz4"
	"github.com/vmihailenco/msgpack/v4"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/encryption"
)

// SessionState is used to store information about the currently authenticated user session
type SessionState struct {
	AccessToken       string     `json:",omitempty" msgpack:"at,omitempty"`
	IDToken           string     `json:",omitempty" msgpack:"it,omitempty"`
	CreatedAt         *time.Time `json:",omitempty" msgpack:"ca,omitempty"`
	ExpiresOn         *time.Time `json:",omitempty" msgpack:"eo,omitempty"`
	RefreshToken      string     `json:",omitempty" msgpack:"rt,omitempty"`
	Email             string     `json:",omitempty" msgpack:"e,omitempty"`
	User              string     `json:",omitempty" msgpack:"u,omitempty"`
	PreferredUsername string     `json:",omitempty" msgpack:"pu,omitempty"`
}

// IsExpired checks whether the session has expired
func (s *SessionState) IsExpired() bool {
	if s.ExpiresOn != nil && !s.ExpiresOn.IsZero() && s.ExpiresOn.Before(time.Now()) {
		return true
	}
	return false
}

// Age returns the age of a session
func (s *SessionState) Age() time.Duration {
	if s.CreatedAt != nil && !s.CreatedAt.IsZero() {
		return time.Now().Truncate(time.Second).Sub(*s.CreatedAt)
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

// EncodeSessionState returns an encrypted, lz4 compressed, MessagePack encoded session
func (s *SessionState) EncodeSessionState(c encryption.Cipher, compress bool) ([]byte, error) {
	packed, err := msgpack.Marshal(s)
	if err != nil {
		return nil, err
	}

	if !compress {
		return c.Encrypt(packed)
	}

	compressed, err := lz4Compress(packed)
	if err != nil {
		return nil, err
	}
	return c.Encrypt(compressed)
}

// DecodeSessionState decodes a LZ4 compressed MessagePack into a Session State
func DecodeSessionState(data []byte, c encryption.Cipher, compressed bool) (*SessionState, error) {
	decrypted, err := c.Decrypt(data)
	if err != nil {
		return nil, err
	}

	packed := decrypted
	if compressed {
		packed, err = lz4Decompress(decrypted)
		if err != nil {
			return nil, err
		}
	}

	var ss *SessionState
	err = msgpack.Unmarshal(packed, &ss)
	if err != nil {
		return nil, err
	}

	return ss, nil
}

// LegacyV5DecodeSessionState decodes a legacy JSON session cookie string into a SessionState
func LegacyV5DecodeSessionState(v string, c encryption.Cipher) (*SessionState, error) {
	var ss SessionState
	err := json.Unmarshal([]byte(v), &ss)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling session: %w", err)
	}

	for _, s := range []*string{
		&ss.User,
		&ss.Email,
		&ss.PreferredUsername,
		&ss.AccessToken,
		&ss.IDToken,
		&ss.RefreshToken,
	} {
		err := into(s, c.Decrypt)
		if err != nil || !utf8.ValidString(*s) {
			return nil, err
		}
	}

	return &ss, nil
}

// codecFunc is a function that takes a []byte and encodes/decodes it
type codecFunc func([]byte) ([]byte, error)

func into(s *string, f codecFunc) error {
	// Do not encrypt/decrypt nil or empty strings
	if s == nil || *s == "" {
		return nil
	}

	d, err := f([]byte(*s))
	if err != nil {
		return err
	}
	*s = string(d)
	return nil
}

// Compress & Decompress with LZ4
// The Compress:Decompress ratio is 1:Many. LZ4 gives fastest decompress speeds
func lz4Compress(payload []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	zw := lz4.NewWriter(nil)
	zw.Header = lz4.Header{
		BlockMaxSize:     65536,
		CompressionLevel: 0,
	}
	zw.Reset(buf)

	reader := bytes.NewReader(payload)
	_, err := io.Copy(zw, reader)
	if err != nil {
		return nil, err
	}
	err = zw.Close()
	if err != nil {
		return nil, err
	}

	compressed, err := ioutil.ReadAll(buf)
	if err != nil {
		return nil, err
	}

	return compressed, nil
}

func lz4Decompress(compressed []byte) ([]byte, error) {
	reader := bytes.NewReader(compressed)
	buf := new(bytes.Buffer)
	zr := lz4.NewReader(nil)
	zr.Reset(reader)
	_, err := io.Copy(buf, zr)
	if err != nil {
		return nil, err
	}

	payload, err := ioutil.ReadAll(buf)
	if err != nil {
		return nil, err
	}

	return payload, nil
}
