package ratelimit

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

type fakeAddr string

func (f fakeAddr) Network() string { return "tcp" }
func (f fakeAddr) String() string  { return string(f) }

func addr(ip string, port int) net.Addr {
	return fakeAddr(fmt.Sprintf("%s:%d", ip, port))
}

// newTestLimiter returns a limiter with a controllable clock.
func newTestLimiter(cfg Config) (*Limiter, func(time.Duration)) {
	l := New(cfg)
	now := time.Now()
	l.now = func() time.Time { return now }
	return l, func(d time.Duration) { now = now.Add(d) }
}

func TestBurstThenRateLimited(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Burst = 5
	cfg.Rate = 1
	l, advance := newTestLimiter(cfg)

	for i := 0; i < 5; i++ {
		if r, release := l.Acquire(addr("1.2.3.4", 1000+i)); r != Allowed {
			t.Fatalf("connection %d within burst refused: %v", i, r)
		} else {
			release()
		}
	}

	if r, _ := l.Acquire(addr("1.2.3.4", 2000)); r != ReasonRate {
		t.Fatalf("expected rate limiting past burst, got %v", r)
	}

	// One token per second.
	advance(1100 * time.Millisecond)
	if r, release := l.Acquire(addr("1.2.3.4", 2001)); r != Allowed {
		t.Fatalf("expected refill to allow a connection, got %v", r)
	} else {
		release()
	}
}

// Source IPs must be limited independently: one abuser must not lock out others.
func TestLimitsArePerSourceIP(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Burst = 2
	cfg.Rate = 0.01
	l, _ := newTestLimiter(cfg)

	for i := 0; i < 2; i++ {
		if r, release := l.Acquire(addr("1.1.1.1", 1000+i)); r != Allowed {
			t.Fatalf("attacker conn %d: %v", i, r)
		} else {
			release()
		}
	}
	if r, _ := l.Acquire(addr("1.1.1.1", 1100)); r != ReasonRate {
		t.Fatal("attacker should be limited")
	}

	if r, release := l.Acquire(addr("2.2.2.2", 1000)); r != Allowed {
		t.Fatalf("unrelated source was affected by another IP's limit: %v", r)
	} else {
		release()
	}
}

// The source port must not be a way to evade limits.
func TestPortDoesNotEvadeLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Burst = 2
	cfg.Rate = 0.01
	l, _ := newTestLimiter(cfg)

	for i := 0; i < 2; i++ {
		_, release := l.Acquire(addr("9.9.9.9", 5000+i))
		release()
	}
	if r, _ := l.Acquire(addr("9.9.9.9", 60000)); r != ReasonRate {
		t.Fatal("changing source port evaded the rate limit")
	}
}

func TestConcurrentHandshakeCap(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxConcurrent = 3
	cfg.Burst = 100
	l, _ := newTestLimiter(cfg)

	var releases []func()
	for i := 0; i < 3; i++ {
		r, release := l.Acquire(addr("5.5.5.5", 1000+i))
		if r != Allowed {
			t.Fatalf("conn %d refused: %v", i, r)
		}
		releases = append(releases, release)
	}

	if r, _ := l.Acquire(addr("5.5.5.5", 2000)); r != ReasonConcurrent {
		t.Fatalf("expected concurrency cap, got %v", r)
	}

	releases[0]()
	if r, release := l.Acquire(addr("5.5.5.5", 2001)); r != Allowed {
		t.Fatalf("slot should free after release, got %v", r)
	} else {
		release()
	}
}

// Releasing twice must not corrupt the in-flight count and free extra slots.
func TestReleaseIsIdempotent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxConcurrent = 1
	cfg.Burst = 100
	l, _ := newTestLimiter(cfg)

	_, release := l.Acquire(addr("6.6.6.6", 1000))
	release()
	release()
	release()

	r, rel := l.Acquire(addr("6.6.6.6", 1001))
	if r != Allowed {
		t.Fatalf("expected one slot, got %v", r)
	}
	rel()
	if r, _ := l.Acquire(addr("6.6.6.6", 1002)); r != ReasonConcurrent && r != Allowed {
		t.Fatalf("unexpected: %v", r)
	}
}

func TestBruteForceTriggersBlock(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxFailures = 5
	cfg.BlockDuration = 10 * time.Minute
	cfg.Burst = 1000
	l, advance := newTestLimiter(cfg)

	a := addr("7.7.7.7", 1000)
	for i := 0; i < 5; i++ {
		l.RecordFailure(a)
	}

	if !l.Blocked(a) {
		t.Fatal("source should be blocked after repeated auth failures")
	}
	if r, _ := l.Acquire(a); r != ReasonBlocked {
		t.Fatalf("blocked source should be refused, got %v", r)
	}

	advance(11 * time.Minute)
	if l.Blocked(a) {
		t.Fatal("block should expire")
	}
	if r, release := l.Acquire(a); r != Allowed {
		t.Fatalf("after block expiry should be allowed, got %v", r)
	} else {
		release()
	}
}

// Failures spread beyond the window must not accumulate into a block: a user
// mistyping occasionally over hours should never be locked out.
func TestFailuresOutsideWindowDoNotAccumulate(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxFailures = 5
	cfg.FailureWindow = time.Minute
	l, advance := newTestLimiter(cfg)

	a := addr("8.8.8.8", 1000)
	for i := 0; i < 10; i++ {
		l.RecordFailure(a)
		advance(2 * time.Minute) // each failure ages out before the next
	}
	if l.Blocked(a) {
		t.Fatal("failures outside the window must not accumulate into a block")
	}
}

// A successful login clears the failure counter, so a client that offers
// several agent keys before the right one is not penalised.
func TestSuccessClearsFailures(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxFailures = 5
	l, _ := newTestLimiter(cfg)

	a := addr("10.0.0.1", 1000)
	for i := 0; i < 4; i++ {
		l.RecordFailure(a)
	}
	l.RecordSuccess(a)
	for i := 0; i < 4; i++ {
		l.RecordFailure(a)
	}
	if l.Blocked(a) {
		t.Fatal("success should reset the failure counter")
	}
}

// Idle sources are evicted, but blocked ones are retained: evicting a blocked
// source would reset its penalty and let an attacker escape by idling.
func TestEvictionKeepsBlockedSources(t *testing.T) {
	cfg := DefaultConfig()
	cfg.IdleTTL = time.Minute
	cfg.MaxFailures = 2
	cfg.BlockDuration = time.Hour
	l, advance := newTestLimiter(cfg)

	blocked := addr("11.11.11.11", 1000)
	l.RecordFailure(blocked)
	l.RecordFailure(blocked)

	idle := addr("12.12.12.12", 1000)
	_, release := l.Acquire(idle)
	release()

	advance(10 * time.Minute)
	l.Acquire(addr("13.13.13.13", 1000)) // triggers eviction sweep

	l.mu.Lock()
	_, idleStillTracked := l.sources["12.12.12.12"]
	l.mu.Unlock()
	if idleStillTracked {
		t.Error("idle source should have been evicted")
	}
	if !l.Blocked(blocked) {
		t.Fatal("SECURITY: blocked source escaped its penalty via eviction")
	}
}

func TestConcurrentUseIsRaceFree(t *testing.T) {
	l := New(DefaultConfig())
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a := addr(fmt.Sprintf("192.168.0.%d", i%10), 1000+i)
			if _, release := l.Acquire(a); release != nil {
				release()
			}
			l.RecordFailure(a)
			l.RecordSuccess(a)
			l.Blocked(a)
		}(i)
	}
	wg.Wait()
}

// A legitimate client with many agent keys offers each in turn; the wrong ones
// fail before the right one succeeds. That must not trip the brute-force block.
// (This is why MaxFailures is well above a typical agent key count, and why a
// success clears the counter.)
func TestManyAgentKeys_DoesNotLockOutLegitimateUser(t *testing.T) {
	cfg := DefaultConfig()
	l, _ := newTestLimiter(cfg)
	a := addr("203.0.113.5", 2222)

	for round := 0; round < 3; round++ {
		// Offer several wrong keys, then the correct one.
		for i := 0; i < cfg.MaxFailures-1; i++ {
			l.RecordFailure(a)
		}
		l.RecordSuccess(a)
		if l.Blocked(a) {
			t.Fatalf("round %d: legitimate user with many agent keys was locked out", round)
		}
	}
}

// A genuine brute-force run -- failures with no success -- must still block.
func TestSustainedFailuresStillBlock(t *testing.T) {
	cfg := DefaultConfig()
	l, _ := newTestLimiter(cfg)
	a := addr("198.51.100.9", 4444)

	for i := 0; i < cfg.MaxFailures; i++ {
		l.RecordFailure(a)
	}
	if !l.Blocked(a) {
		t.Fatal("sustained failures must trigger a block")
	}
}
