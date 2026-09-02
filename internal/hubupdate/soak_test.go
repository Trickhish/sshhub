package hubupdate

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

func checker(tag string, age time.Duration) updateChecker {
	return func(soak time.Duration) (string, time.Time, error) {
		return tag, time.Now().Add(-age), nil
	}
}

func TestSoak_YoungReleaseIsNotInstalled(t *testing.T) {
	installed := ""
	ok := applyIfDueWith(48*time.Hour,
		checker("v0.5.0", 1*time.Hour),
		func(tag string) error { installed = tag; return nil },
		func() string { return "0.4.1" })

	if ok || installed != "" {
		t.Fatalf("a 1h-old release must not install under a 48h soak (installed %q)", installed)
	}
}

func TestSoak_MatureReleaseIsInstalled(t *testing.T) {
	installed := ""
	ok := applyIfDueWith(48*time.Hour,
		checker("v0.5.0", 72*time.Hour),
		func(tag string) error { installed = tag; return nil },
		func() string { return "0.4.1" })

	if !ok || installed != "v0.5.0" {
		t.Fatalf("a 72h-old release should install under a 48h soak (ok=%v installed=%q)", ok, installed)
	}
}

// soak == 0 means install immediately.
func TestSoak_ZeroInstallsImmediately(t *testing.T) {
	installed := ""
	ok := applyIfDueWith(0,
		checker("v0.5.0", time.Minute),
		func(tag string) error { installed = tag; return nil },
		func() string { return "0.4.1" })

	if !ok || installed != "v0.5.0" {
		t.Fatalf("soak 0 should install a brand-new release (ok=%v installed=%q)", ok, installed)
	}
}

// THE KEY PROPERTY: the soak tracks the CURRENT latest release, not the one
// that started the wait. If a broken release is superseded during its soak, the
// replacement is what installs -- so an emergency fix is not held back behind
// the release it fixes.
func TestSoak_InstallsNewestNotTheOneThatStartedTheWait(t *testing.T) {
	// Cycle 1: v0.5.0 is 1h old -> too young, nothing installs.
	// Cycle 2: v0.5.0 was broken and replaced by v0.5.1, now mature.
	cycle := 0
	check := func(soak time.Duration) (string, time.Time, error) {
		cycle++
		if cycle == 1 {
			return "v0.5.0", time.Now().Add(-1 * time.Hour), nil
		}
		return "v0.5.1", time.Now().Add(-72 * time.Hour), nil
	}

	installed := ""
	install := func(tag string) error { installed = tag; return nil }
	cur := func() string { return "0.4.1" }

	if applyIfDueWith(48*time.Hour, check, install, cur) {
		t.Fatal("first cycle should not install a 1h-old release")
	}
	if !applyIfDueWith(48*time.Hour, check, install, cur) {
		t.Fatal("second cycle should install")
	}
	if installed != "v0.5.1" {
		t.Fatalf("installed %q; the emergency fix v0.5.1 should supersede the broken v0.5.0", installed)
	}
}

// Without a publication time the soak cannot be honoured, so it must fail
// closed rather than install anyway.
func TestSoak_MissingPublishTimeDefersUpdate(t *testing.T) {
	installed := ""
	ok := applyIfDueWith(48*time.Hour,
		func(soak time.Duration) (string, time.Time, error) {
			return "v0.5.0", time.Time{}, nil // zero time
		},
		func(tag string) error { installed = tag; return nil },
		func() string { return "0.4.1" })

	if ok || installed != "" {
		t.Fatalf("a release with no publication time must not install under a soak (installed %q)", installed)
	}
}

func TestSoak_OlderReleaseNeverInstalled(t *testing.T) {
	installed := ""
	ok := applyIfDueWith(0,
		checker("v0.3.0", 999*time.Hour),
		func(tag string) error { installed = tag; return nil },
		func() string { return "0.4.1" })

	if ok || installed != "" {
		t.Fatalf("must not downgrade (installed %q)", installed)
	}
}

func TestSoak_FetchErrorIsNotFatal(t *testing.T) {
	ok := applyIfDueWith(48*time.Hour,
		func(soak time.Duration) (string, time.Time, error) {
			return "", time.Time{}, fmt.Errorf("network down")
		},
		func(tag string) error { t.Fatal("must not install after a fetch error"); return nil },
		func() string { return "0.4.1" })
	if ok {
		t.Fatal("fetch error should not report an update")
	}
}

// A negative soak disables updates: nothing is fetched or installed.
func TestSoak_DisabledNeverInstalls(t *testing.T) {
	fetched := false
	installed := ""
	ok := applyIfDueWith(-1,
		func(soak time.Duration) (string, time.Time, error) {
			fetched = true
			return "v9.9.9", time.Now().Add(-999 * time.Hour), nil
		},
		func(tag string) error { installed = tag; return nil },
		func() string { return "0.4.1" })

	if ok || installed != "" {
		t.Fatalf("updates are disabled; nothing may install (installed %q)", installed)
	}
	if fetched {
		t.Error("with updates disabled the hub should not even query for releases")
	}
}

// StartAutoUpdater must not spawn a polling goroutine when disabled.
func TestSoak_DisabledStartsNoGoroutine(t *testing.T) {
	before := runtime.NumGoroutine()
	StartAutoUpdater(time.Hour, -1)
	time.Sleep(50 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("disabled updater started %d goroutine(s)", after-before)
	}
}
