package config

import (
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// An absent field must mean the safe default, NOT instant updates.
func TestAutoUpdateWait_AbsentMeansDefault(t *testing.T) {
	var c Config
	if err := yaml.Unmarshal([]byte("listen:\n  ssh: \":22\"\n"), &c); err != nil {
		t.Fatal(err)
	}
	if c.AutoUpdateWait != nil {
		t.Fatal("absent field should leave the pointer nil")
	}
	if got := c.ResolvedAutoUpdateWait(); got != DefaultAutoUpdateWait {
		t.Fatalf("absent auto_update_wait resolved to %s, want %s", got, DefaultAutoUpdateWait)
	}
}

// An explicit 0 must mean instant, and must be distinguishable from absent.
func TestAutoUpdateWait_ExplicitZeroMeansInstant(t *testing.T) {
	for _, y := range []string{
		"auto_update_wait: \"0\"\n",
		"auto_update_wait: 0\n",
	} {
		var c Config
		if err := yaml.Unmarshal([]byte(y), &c); err != nil {
			t.Fatalf("%q: %v", y, err)
		}
		if c.AutoUpdateWait == nil {
			t.Fatalf("%q: explicit 0 must not be indistinguishable from absent", y)
		}
		if got := c.ResolvedAutoUpdateWait(); got != 0 {
			t.Fatalf("%q: resolved to %s, want 0", y, got)
		}
	}
}

func TestAutoUpdateWait_Durations(t *testing.T) {
	cases := map[string]time.Duration{
		"48h":      48 * time.Hour,
		"90m":      90 * time.Minute,
		"1h30m":    90 * time.Minute,
		"0":        0,
		"false":    AutoUpdateDisabled,
		"False":    AutoUpdateDisabled,
		"no":       AutoUpdateDisabled,
		"off":      AutoUpdateDisabled,
		"never":    AutoUpdateDisabled,
		"disabled": AutoUpdateDisabled,
	}
	for in, want := range cases {
		c := Config{AutoUpdateWait: &autoUpdateWaitValue{raw: in}}
		if got := c.ResolvedAutoUpdateWait(); got != want {
			t.Errorf("auto_update_wait %q = %s, want %s", in, got, want)
		}
	}
}

// The disabled sentinel must be distinct from 0: 0 means "install
// immediately", which is the opposite of disabled.
func TestAutoUpdateWait_DisabledIsNotZero(t *testing.T) {
	if AutoUpdateDisabled == 0 {
		t.Fatal("disabled must not be equal to 0 (install immediately)")
	}
	off := Config{AutoUpdateWait: &autoUpdateWaitValue{raw: "false"}}
	instant := Config{AutoUpdateWait: &autoUpdateWaitValue{raw: "0"}}
	if off.ResolvedAutoUpdateWait() == instant.ResolvedAutoUpdateWait() {
		t.Fatal("\"false\" and \"0\" must not resolve to the same behaviour")
	}
}

// Unquoted YAML scalars must work: `false` is a bool and `0` an int to the
// parser, so the natural spellings have to be accepted.
func TestAutoUpdateWait_UnquotedYAMLScalars(t *testing.T) {
	cases := map[string]time.Duration{
		"auto_update_wait: false\n":   AutoUpdateDisabled,
		"auto_update_wait: 0\n":       0,
		"auto_update_wait: 48h\n":     48 * time.Hour,
		"auto_update_wait: \"48h\"\n": 48 * time.Hour,
	}
	for y, want := range cases {
		var c Config
		if err := yaml.Unmarshal([]byte(y), &c); err != nil {
			t.Errorf("%q failed to parse: %v", y, err)
			continue
		}
		if got := c.ResolvedAutoUpdateWait(); got != want {
			t.Errorf("%q resolved to %s, want %s", y, got, want)
		}
	}
}

// A typo must be rejected, not silently treated as the default -- that would
// leave the operator believing a setting applied when it did not.
func TestAutoUpdateWait_InvalidRejected(t *testing.T) {
	// "-1" and "" are rejected rather than guessed at: a negative is more
	// likely a duration typo than a request to disable, and an empty value is
	// equally readable as "unset" or "disabled". Guessing either way risks
	// silently leaving updates on or off against the operator's intent.
	for _, bad := range []string{"48hours", "soon", "-1h", "-1", "48 h", "", "  "} {
		cfg := Config{
			Listen:         Listen{SSH: ":22", Control: ":7000"},
			HostKey:        "/k",
			Backends:       []Backend{{ID: "b", Mode: "reverse"}},
			Routes:         []Route{{Username: "*", Backend: "b"}},
			AutoUpdateWait: &autoUpdateWaitValue{raw: bad},
		}
		if err := cfg.Validate(); err == nil {
			t.Errorf("auto_update_wait %q must be rejected", bad)
		}
	}
}
