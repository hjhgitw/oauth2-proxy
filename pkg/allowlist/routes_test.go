package allowlist

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddGlobalRegex(t *testing.T) {
	testCases := map[string]struct {
		Regexes []string
		Errors  []string
	}{
		"Non-overlapping regex routes": {
			Regexes: []string{
				"/foo",
				"/foo/bar",
				"^/foo/bar$",
				"/crazy/(?:regex)?/[^/]+/stuff$",
			},
			Errors: nil,
		},
		"Overlapping regex routes removes duplicates": {
			Regexes: []string{
				"/foo",
				"/foo/bar",
				"^/foo/bar$",
				"/crazy/(?:regex)?/[^/]+/stuff$",
				"^/foo/bar$",
			},
			Errors: nil,
		},
		"Bad regexes do not compile": {
			Regexes: []string{
				"/(foo",
				"/foo/bar)",
				"^]/foo/bar[$",
				"^]/foo/bar[$",
			},
			Errors: []string{
				"error compiling regex //(foo/: error parsing regexp: missing closing ): `/(foo`",
				"error compiling regex //foo/bar)/: error parsing regexp: unexpected ): `/foo/bar)`",
				"error compiling regex /^]/foo/bar[$/: error parsing regexp: missing closing ]: `[$`",
				"error compiling regex /^]/foo/bar[$/: error parsing regexp: missing closing ]: `[$`",
			},
		},
	}

	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			routes := NewRoutes()
			for i, regex := range tc.Regexes {
				err := routes.AddGlobalRegex(regex)
				if tc.Errors == nil {
					assert.NoError(t, err)
				} else {
					assert.EqualError(t, err, tc.Errors[i])
				}
			}
		})
	}
}

func TestAddMethodRegex(t *testing.T) {
	testCases := map[string]struct {
		Regexes [][]string
		Errors  []string
	}{
		"Non-overlapping regex routes": {
			Regexes: [][]string{
				{"GET", "/foo"},
				{"POST", "/foo/bar"},
				{"PUT", "^/foo/bar$"},
				{"DELETE", "/crazy/(?:regex)?/[^/]+/stuff$"},
			},
			Errors: nil,
		},
		"Overlapping regex routes removes duplicates": {
			Regexes: [][]string{
				{"GET", "/foo"},
				{"POST", "/foo/bar"},
				{"PUT", "^/foo/bar$"},
				{"DELETE", "/crazy/(?:regex)?/[^/]+/stuff$"},
				{"GET", "/foo"},
			},
			Errors: nil,
		},
		"Bad regexes do not compile": {
			Regexes: [][]string{
				{"POST", "/(foo"},
				{"OPTIONS", "/foo/bar)"},
				{"GET", "^]/foo/bar[$"},
				{"GET", "^]/foo/bar[$"},
			},
			Errors: []string{
				"error compiling regex //(foo/: error parsing regexp: missing closing ): `/(foo`",
				"error compiling regex //foo/bar)/: error parsing regexp: unexpected ): `/foo/bar)`",
				"error compiling regex /^]/foo/bar[$/: error parsing regexp: missing closing ]: `[$`",
				"error compiling regex /^]/foo/bar[$/: error parsing regexp: missing closing ]: `[$`",
			},
		},
	}

	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			routes := NewRoutes()
			for i, methodRegex := range tc.Regexes {
				err := routes.AddMethodRegex(methodRegex[0], methodRegex[1])
				if tc.Errors == nil {
					assert.NoError(t, err)
				} else {
					assert.EqualError(t, err, tc.Errors[i])
				}
			}
		})
	}
}

func TestRoutes_IsTrusted(t *testing.T) {
	testCases := map[string]struct {
		Regexes  [][]string
		Method   string
		Path     string
		Expected bool
	}{
		"Non-overlapping regex routes with match": {
			Regexes: [][]string{
				{"ALL", "/foo"},
				{"POST", "/foo/bar"},
				{"PUT", "^/foo/bar$"},
				{"DELETE", "/crazy/(?:regex)?/[^/]+/stuff$"},
			},
			Method:   "GET",
			Path:     "/foo",
			Expected: true,
		},
		"Overlapping regex routes removes duplicates with match": {
			Regexes: [][]string{
				{"GET", "/foo"},
				{"ALL", "/foo/bar"},
				{"ALL", "^/foo/bar$"},
				{"DELETE", "/crazy/(?:regex)?/[^/]+/stuff$"},
				{"GET", "/foo"},
			},
			Method:   "GET",
			Path:     "/foo",
			Expected: true,
		},
		"Global match": {
			Regexes: [][]string{
				{"ALL", "/foo/bar"},
			},
			Method:   "POST",
			Path:     "/foo/bar/baz",
			Expected: true,
		},
		"Method match": {
			Regexes: [][]string{
				{"DELETE", "/crazy/(?:regex)?/[^/]+/stuff$"},
			},
			Method:   "DELETE",
			Path:     "/crazy/regex/wilcard/stuff",
			Expected: true,
		},
		"Wrong method is not trusted": {
			Regexes: [][]string{
				{"POST", "/foo/bar"},
				{"GET", "^/foo/bar$"},
			},
			Method:   "GET",
			Path:     "/foo/bar/baz",
			Expected: false,
		},
		"Wrong path is not trusted": {
			Regexes: [][]string{
				{"ALL", "/foo"},
				{"POST", "/foo/bar"},
				{"PUT", "^/foo/bar$"},
				{"DELETE", "/crazy/(?:regex)?/[^/+]/stuff$"},
			},
			Method:   "GET",
			Path:     "/",
			Expected: false,
		},
	}
	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			routes := NewRoutes()
			for _, methodRegex := range tc.Regexes {
				if methodRegex[0] != "ALL" {
					err := routes.AddMethodRegex(methodRegex[0], methodRegex[1])
					assert.NoError(t, err)
				} else {
					err := routes.AddGlobalRegex(methodRegex[1])
					assert.NoError(t, err)
				}
			}
			req := &http.Request{
				Method: tc.Method,
				URL: &url.URL{
					Path: tc.Path,
				},
			}
			assert.Equal(t, tc.Expected, routes.IsTrusted(req))
		})
	}
}

func TestRoutes_LogMessages(t *testing.T) {
	testCases := map[string]struct {
		Regexes      [][]string
		ExpectedSize int
	}{
		"Non-overlapping regex routes": {
			Regexes: [][]string{
				{"ALL", "/foo"},
				{"ALL", "/foo/bar"},
				{"PUT", "^/foo/bar$"},
				{"POST", "/crazy/(?:regex)?/[^/]+/stuff$"},
			},
			ExpectedSize: 4,
		},
		"Overlapping regex routes removes duplicates": {
			Regexes: [][]string{
				{"ALL", "/foo"},
				{"ALL", "/foo/bar"},
				{"POST", "^/foo/bar$"},
				{"DELETE", "/crazy/(?:regex)?/[^/]+/stuff$"},
				{"ALL", "/foo"},
			},
			ExpectedSize: 4,
		},
	}
	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			routes := NewRoutes()
			for _, methodRegex := range tc.Regexes {
				if methodRegex[0] != "ALL" {
					err := routes.AddMethodRegex(methodRegex[0], methodRegex[1])
					assert.NoError(t, err)
				} else {
					err := routes.AddGlobalRegex(methodRegex[1])
					assert.NoError(t, err)
				}
			}
			msgs := routes.LogMessages()
			assert.Equal(t, tc.ExpectedSize, len(msgs))
			for _, methodRegex := range tc.Regexes {
				expected := fmt.Sprintf(
					"Skipping auth for allowlisted route: Method => %s, Path Regex => %q",
					methodRegex[0],
					methodRegex[1])
				assert.Contains(t, msgs, expected)
			}
		})
	}
}
