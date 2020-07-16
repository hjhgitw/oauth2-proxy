package allowlist

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddTrustedIP(t *testing.T) {
	testCases := map[string]struct {
		TrustedIPs []string
		Errors     []string
	}{
		"Non-overlapping valid IPs": {
			TrustedIPs: []string{
				"127.0.0.1",
				"10.32.0.1/32",
				"43.36.201.0/24",
				"::1",
				"2a12:105:ee7:9234:0:0:0:0/64",
			},
			Errors: nil,
		},
		"Overlapping valid IPs": {
			TrustedIPs: []string{
				"135.180.78.199",
				"135.180.78.199/32",
				"d910:a5a1:16f8:ddf5:e5b9:5cef:a65e:41f4",
				"d910:a5a1:16f8:ddf5:e5b9:5cef:a65e:41f4/128",
			},
			Errors: nil,
		},
		"Invalid IPs": {
			TrustedIPs: []string{"[::1]", "alkwlkbn/32"},
			Errors: []string{
				"could not parse IP network ([::1])",
				"could not parse IP network (alkwlkbn/32)",
			},
		},
	}

	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			ips := NewIPs(nil)
			for i, trustedIP := range tc.TrustedIPs {
				err := ips.AddTrustedIP(trustedIP)
				if tc.Errors == nil {
					assert.NoError(t, err)
				} else {
					assert.EqualError(t, err, tc.Errors[i])
				}
			}
		})
	}
}

func TestIPs_IsTrusted(t *testing.T) {
	testCases := map[string]struct {
		TrustedIPs []string
		RequestIP  string
		Expected   bool
	}{
		"Matching request IP": {
			TrustedIPs: []string{
				"127.0.0.1",
				"10.32.0.1/32",
				"43.36.201.0/24",
				"::1",
				"2a12:105:ee7:9234:0:0:0:0/64",
			},
			RequestIP: "43.36.201.100",
			Expected:  true,
		},
		"Overlapping valid IPs with matching request": {
			TrustedIPs: []string{
				"135.180.78.199",
				"135.180.78.199/32",
				"d910:a5a1:16f8:ddf5:e5b9:5cef:a65e:41f4",
				"d910:a5a1:16f8:ddf5:e5b9:5cef:a65e:41f4/128",
			},
			RequestIP: "135.180.78.199",
			Expected:  true,
		},
		"Non-matching request IP": {
			TrustedIPs: []string{
				"127.0.0.1",
				"10.32.0.1/32",
				"43.36.201.0/24",
			},
			RequestIP: "10.32.0.2",
			Expected:  false,
		},
	}
	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			ips := NewIPs(nil)
			for _, trustedIP := range tc.TrustedIPs {
				err := ips.AddTrustedIP(trustedIP)
				assert.NoError(t, err)
			}
			req := &http.Request{
				RemoteAddr: fmt.Sprintf("%s:443", tc.RequestIP),
			}
			assert.Equal(t, tc.Expected, ips.IsTrusted(req))
		})
	}
}

func TestIPs_LogMessages(t *testing.T) {
	testCases := map[string]struct {
		TrustedIPs []string
		Messages   []string
	}{
		"Non-overlapping valid IPs": {
			TrustedIPs: []string{
				"127.0.0.1",
				"10.32.0.1/32",
				"43.36.201.0/24",
				"::1",
				"2a12:105:ee7:9234:0:0:0:0/64",
			},
		},
		"Overlapping valid IPs": {
			TrustedIPs: []string{
				"135.180.78.199",
				"135.180.78.199/32",
				"d910:a5a1:16f8:ddf5:e5b9:5cef:a65e:41f4",
				"d910:a5a1:16f8:ddf5:e5b9:5cef:a65e:41f4/128",
			},
		},
	}
	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			ips := NewIPs(nil)
			for _, trustedIP := range tc.TrustedIPs {
				err := ips.AddTrustedIP(trustedIP)
				assert.NoError(t, err)
			}
			for i, msg := range ips.LogMessages() {
				expected := fmt.Sprintf("Skipping auth for allowlisted IP/CIDR range: %s", tc.TrustedIPs[i])
				assert.Equal(t, expected, msg)
			}
		})
	}
}
