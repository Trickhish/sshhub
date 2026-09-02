package hubupdate

import "testing"

func TestIsNewer(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
		why             string
	}{
		{"0.4.0", "0.3.0", true, "newer minor"},
		{"1.0.0", "0.9.9", true, "newer major"},
		{"0.3.1", "0.3.0", true, "newer patch"},
		{"0.10.0", "0.9.0", true, "numeric, not lexicographic"},
		{"v0.4.0", "0.3.0", true, "v prefix tolerated"},
		{"0.3.0", "0.3.0", false, "equal"},

		// The regression: an older 'latest' must NOT be advertised as an update,
		// or a staged rollout would downgrade an already-updated agent back into
		// a vulnerable build.
		{"0.3.0", "0.4.0", false, "older must not be advertised"},
		{"0.9.0", "0.10.0", false, "older, numeric comparison"},
		{"0.3.0", "1.0.0", false, "older major"},

		{"", "0.3.0", false, "empty latest"},
		{"0.3.0", "", false, "empty current"},
		{"garbage", "0.3.0", false, "malformed is never newer"},
	}
	for _, c := range cases {
		if got := IsNewer(c.latest, c.current); got != c.want {
			t.Errorf("IsNewer(%q, %q) = %v, want %v (%s)", c.latest, c.current, got, c.want, c.why)
		}
	}
}

// A pre-release must not be considered newer than its final release.
func TestPreReleaseOrdering(t *testing.T) {
	if IsNewer("0.4.0-rc1", "0.4.0") {
		t.Error("0.4.0-rc1 must not be newer than 0.4.0")
	}
}
