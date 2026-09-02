package routing

import (
	"testing"

	"github.com/Trickhish/sshhub/internal/config"
)

func TestParseRequest(t *testing.T) {
	cases := []struct {
		in       string
		username string
		hostname string
	}{
		{"alice", "alice", ""},
		{"alice@web1", "alice", "web1"},
		{"alice@web1.example.com", "alice", "web1.example.com"},
		{"alice@bob@web1", "alice@bob", "web1"},
	}
	for _, c := range cases {
		r := ParseRequest(c.in)
		if r.Username != c.username || r.Hostname != c.hostname {
			t.Errorf("ParseRequest(%q) = %+v, want user=%q host=%q", c.in, r, c.username, c.hostname)
		}
	}
}

func TestResolve(t *testing.T) {
	router := New([]config.Route{
		{Match: config.Match{Username: "deploy", Hostname: "web1.example.com"}, Backend: "web1"},
		{Match: config.Match{Username: "backup"}, Backend: "db1"},
		{Match: config.Match{Username: "*"}, Backend: "fallback"},
	})

	cases := []struct {
		user    string
		backend string
		ok      bool
	}{
		{"deploy@web1.example.com", "web1", true},
		{"backup", "db1", true},
		{"backup@whatever", "db1", true},
		{"unknown", "fallback", true},
		{"deploy@other", "fallback", true},
	}
	for _, c := range cases {
		got, ok := router.Resolve(ParseRequest(c.user))
		if got != c.backend || ok != c.ok {
			t.Errorf("Resolve(%q) = (%q, %v), want (%q, %v)", c.user, got, ok, c.backend, c.ok)
		}
	}
}

func TestResolveNoMatch(t *testing.T) {
	router := New([]config.Route{
		{Match: config.Match{Username: "alice"}, Backend: "web1"},
	})
	if _, ok := router.Resolve(ParseRequest("bob")); ok {
		t.Fatal("expected no match")
	}
}

// The Unix account a session runs as must come from the matched route's
// end_user, never from the client-supplied login string. A client naming
// itself "root" must not obtain root unless a route says so.
func TestResolveRoute_EndUserComesFromConfigNotClient(t *testing.T) {
	router := New([]config.Route{
		{Match: config.Match{Username: "admin", Hostname: "w1"}, Backend: "w1", EndUser: "root"},
		{Match: config.Match{Hostname: "w1"}, Backend: "w1", EndUser: "deploy"},
		{Match: config.Match{Hostname: "w2"}, Backend: "w2"},
	})

	cases := []struct {
		login   string
		backend string
		endUser string
	}{
		{"admin@w1", "w1", "root"},
		{"deploy@w1", "w1", "deploy"},
		// Client claims "root" but only the second w1 rule matches -> deploy.
		{"root@w1", "w1", "deploy"},
		// No end_user configured -> default, not the client's "root".
		{"root@w2", "w2", "root"},
		{"anyone@w2", "w2", "root"},
	}
	for _, c := range cases {
		rt, ok := router.ResolveRoute(ParseRequest(c.login))
		if !ok {
			t.Fatalf("ResolveRoute(%q): no match", c.login)
		}
		if rt.Backend != c.backend || rt.ResolvedEndUser() != c.endUser {
			t.Errorf("ResolveRoute(%q) = backend %q end_user %q, want %q/%q",
				c.login, rt.Backend, rt.ResolvedEndUser(), c.backend, c.endUser)
		}
	}
}
