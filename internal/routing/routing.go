// Package routing resolves incoming SSH requests to a backend.
package routing

import (
	"strings"

	"github.com/Trickhish/sshhub/internal/config"
)

// Router matches requests against a list of routing rules.
type Router struct {
	rules []rule
}

type rule struct {
	usernamePattern string
	hostnamePattern string
	route           config.Route
}

// New builds a Router from the configured routes.
func New(routes []config.Route) *Router {
	r := &Router{}
	for _, rt := range routes {
		r.rules = append(r.rules, rule{
			usernamePattern: normalize(rt.Match.Username),
			hostnamePattern: normalize(rt.Match.Hostname),
			route:           rt,
		})
	}
	return r
}

// normalize turns an empty pattern into the catch-all wildcard.
func normalize(p string) string {
	if p == "" {
		return "*"
	}
	return p
}

// Request is a parsed SSH login: username and optional hostname.
type Request struct {
	Username string
	Hostname string
}

// ParseRequest splits an SSH user string into username and hostname.
// A user of the form "alice@web1" yields Username "alice", Hostname "web1".
// Without an "@" the Hostname is empty.
func ParseRequest(user string) Request {
	if i := strings.LastIndex(user, "@"); i >= 0 {
		return Request{Username: user[:i], Hostname: user[i+1:]}
	}
	return Request{Username: user}
}

// ResolveRoute returns the first matching route, or false if none matches.
// Rules are evaluated in order; the first match wins. Callers need the whole
// route (not just the backend id) because the route carries end_user, which
// determines the Unix account the session runs as.
func (r *Router) ResolveRoute(req Request) (config.Route, bool) {
	for _, rl := range r.rules {
		if matchPattern(rl.usernamePattern, req.Username) &&
			matchPattern(rl.hostnamePattern, req.Hostname) {
			return rl.route, true
		}
	}
	return config.Route{}, false
}

// Resolve returns the backend id for a request, or false if none matches.
func (r *Router) Resolve(req Request) (string, bool) {
	rt, ok := r.ResolveRoute(req)
	if !ok {
		return "", false
	}
	return rt.Backend, true
}

// matchPattern performs a simple glob match where "*" matches any rune
// sequence. An empty pattern was normalized to "*" by New.
func matchPattern(pattern, value string) bool {
	return globMatch(pattern, value)
}

func globMatch(pattern, value string) bool {
	// Iterative wildcard matcher.
	var p, v int
	star, mark := -1, -1
	for v < len(value) {
		if p < len(pattern) && pattern[p] == '*' {
			star = p
			mark = v
			p++
		} else if p < len(pattern) && pattern[p] == value[v] {
			p++
			v++
		} else if star >= 0 {
			p = star + 1
			mark++
			v = mark
		} else {
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
