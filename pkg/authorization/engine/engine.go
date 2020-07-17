package engine

import (
	"github.com/oauth2-proxy/oauth2-proxy/pkg/authorization"
	"math/rand"
	"net/http"

	ipapi "github.com/oauth2-proxy/oauth2-proxy/pkg/apis/ip"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/authorization/index"
)

type RulesEngine struct {
	Rules   []*authorization.Rule
	Indices []index.Index

	// Whether or not to trigger indexing & rule prioritization
	optimize bool

	// Index singletons
	pathIndex    *index.PathIndex
	methodsIndex *index.MethodsIndex
	ipsIndex     *index.IPsIndex

	// ipParser needed for IP Rules
	ipParser ipapi.RealClientIPParser
}

func NewRulesEngine(ipParser ipapi.RealClientIPParser) *RulesEngine {
	return &RulesEngine{
		Rules:   []*authorization.Rule{},
		Indices: []index.Index{},

		optimize: false,

		pathIndex:    index.NewPathIndex(),
		methodsIndex: index.NewMethodsIndex(),
		ipsIndex:     index.NewIPsIndex(ipParser),

		ipParser: ipParser,
	}
}

func (e *RulesEngine) AddRule(rule *authorization.Rule) {
	e.Rules = append(e.Rules, rule)

	if e.pathIndex.IndexRule(rule) {
		e.activateIndex(e.pathIndex)
	}
	if e.methodsIndex.IndexRule(rule) {
		e.activateIndex(e.methodsIndex)
	}
	if e.ipsIndex.IndexRule(rule) {
		e.activateIndex(e.ipsIndex)
	}

	if len(e.Rules) > 5 {
		e.optimize = true
	}
}

func (e *RulesEngine) Allow(req *http.Request) bool {
	allower := func(rule *authorization.Rule, r *http.Request) bool {
		return rule.Allow(r, e.ipParser)
	}
	return e.check(req, allower)
}

func (e *RulesEngine) Deny(req *http.Request) bool {
	denier := func(rule *authorization.Rule, r *http.Request) bool {
		return rule.Deny(r, e.ipParser)
	}
	return e.check(req, denier)
}

// check compares a http.Request against our rules engine with a checker
// function (likely a wrapper around Allow()/Deny().
//
// If `optimize` is false, it will perform a O(N) scan of all rules.
// Otherwise it will use the activated Indices. The indices and rules will
// attempt greedy reordering to place more active Rules at the front of the
// list.
func (e *RulesEngine) check(req *http.Request, checker func(*authorization.Rule, *http.Request) bool) bool {
	if !e.optimize {
		for _, rule := range e.Rules {
			if checker(rule, req) {
				return true
			}
		}
		return false
	}

	// Occasionally reorder the indices to get high hit rate indices first
	if rand.Intn(100) == 1 {
		e.prioritizeIndices()
	}

	// TODO (@NickMeves): Investigate LRU cache of Allow(req) == false results
	//  to skip this whole lookup process

	// Memoize rules we've already checked
	checked := map[string]struct{}{}
	for _, idx := range e.Indices {
		indexRules := idx.MatchRules(req)
		for i, rule := range indexRules {
			if _, ok := checked[rule.ID]; ok {
				continue
			}
			if checker(rule, req) {
				prioritizeRule(indexRules, i)
				return true
			}
			checked[rule.ID] = struct{}{}
		}
	}

	// No index matches, check remaining unchecked rules
	for _, rule := range e.Rules {
		if _, ok := checked[rule.ID]; ok {
			continue
		}
		if checker(rule, req) {
			// DO NOT prioritizeRules on the global list
			// Avoids any rare concurrency issues
			return true
		}
	}

	return false
}

// activateIndex promotes an Index singleton into the active indices
// This occurs as added rules are indexed by a given index
func (e *RulesEngine) activateIndex(idx index.Index) {
	for _, active := range e.Indices {
		if active.Name() == idx.Name() {
			return
		}
	}
	e.Indices = append(e.Indices, idx)
}

// sortIndices semi-sorts the Indices from high to low hit rates
// It is intentionally O(N) and not perfect, over time it will
// sort itself well enough.
//
// This doesn't need to lock, if we miss an index on a swap/range
// parallel operation, the Rule will get checked in the global
// fallback
func (e *RulesEngine) prioritizeIndices() {
	for i := 1; i < len(e.Indices); i++ {
		if e.Indices[i-1].Hits() < e.Indices[i].Hits() {
			e.Indices[i-1], e.Indices[i] = e.Indices[i], e.Indices[i-1]
		}
	}
}

// prioritizeRule will slowly bubble up rules with higher
// hit rates to the front of their queues.
//
// This doesn't need to lock, if we miss an index on a swap/range
// parallel operation, the Rule will get checked in the global
// fallback
func prioritizeRule(rules []*authorization.Rule, i int) {
	if i > 0 && rules[i-1].Hits() < rules[i].Hits() {
		rules[i-1], rules[i] = rules[i], rules[i-1]
	}
}
