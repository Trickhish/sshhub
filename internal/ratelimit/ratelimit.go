// Package ratelimit provides per-source connection throttling for the hub's
// public SSH listener.
//
// It is a availability control, not an authentication one: it bounds how fast an
// unauthenticated peer can force the hub to do expensive work (SSH handshakes,
// and the backend round-trip each offered key triggers). It deliberately does
// NOT decide who may log in.
//
// Limitations worth knowing:
//   - State is per-process and in-memory, so it resets when the hub restarts.
//   - Keying is by source IP, so a distributed source or a shared NAT is either
//     under-limited or over-limited respectively.
package ratelimit

import (
	"net"
	"sync"
	"time"
)

// Config tunes the limiter. The zero value is not useful; use DefaultConfig.
type Config struct {
	// Rate is the sustained connections/second allowed per source IP.
	Rate float64
	// Burst is how many connections a source may make back-to-back before Rate
	// applies. Sized so a normal client offering several agent keys, or a few
	// quick sessions, is never throttled.
	Burst float64
	// MaxConcurrent caps simultaneous in-flight (pre-auth) handshakes per IP.
	// Handshakes are the expensive part, so this bounds resource use even when
	// the connection rate is within budget.
	MaxConcurrent int
	// MaxFailures is how many failed authentications a source may accumulate
	// within FailureWindow before being blocked for BlockDuration.
	MaxFailures int
	// FailureWindow is the sliding window over which failures are counted.
	FailureWindow time.Duration
	// BlockDuration is how long a source stays blocked after tripping
	// MaxFailures.
	BlockDuration time.Duration
	// IdleTTL is how long an inactive source's state is retained before being
	// evicted, bounding memory against a spray of one-shot source addresses.
	IdleTTL time.Duration
}

// DefaultConfig returns limits intended to be generous for real users and
// hostile to brute force.
func DefaultConfig() Config {
	return Config{
		Rate:          0.5, // one connection every 2s sustained
		Burst:         10,  // but 10 back-to-back are fine
		MaxConcurrent: 8,
		MaxFailures:   10,
		FailureWindow: 5 * time.Minute,
		BlockDuration: 15 * time.Minute,
		IdleTTL:       30 * time.Minute,
	}
}

// Reason describes why a connection was refused.
type Reason int

const (
	Allowed Reason = iota
	ReasonRate
	ReasonConcurrent
	ReasonBlocked
)

func (r Reason) String() string {
	switch r {
	case ReasonRate:
		return "connection rate exceeded"
	case ReasonConcurrent:
		return "too many concurrent handshakes"
	case ReasonBlocked:
		return "temporarily blocked after repeated authentication failures"
	default:
		return "allowed"
	}
}

type source struct {
	tokens     float64
	lastRefill time.Time
	inFlight   int
	failures   []time.Time
	blockedTil time.Time
	lastSeen   time.Time
}

// Limiter tracks per-source-IP connection state.
type Limiter struct {
	cfg Config
	now func() time.Time // injectable for tests

	mu      sync.Mutex
	sources map[string]*source
}

// New creates a Limiter.
func New(cfg Config) *Limiter {
	return &Limiter{
		cfg:     cfg,
		now:     time.Now,
		sources: make(map[string]*source),
	}
}

// key reduces an address to its source IP, so a peer cannot evade limits by
// varying its ephemeral source port.
func key(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// get returns the source state, creating it if needed. Caller holds mu.
func (l *Limiter) get(k string, now time.Time) *source {
	s, ok := l.sources[k]
	if !ok {
		s = &source{tokens: l.cfg.Burst, lastRefill: now}
		l.sources[k] = s
	}
	s.lastSeen = now
	return s
}

// Acquire decides whether to accept a new connection from addr.
//
// On Allowed the caller MUST call the returned release func exactly once, when
// the handshake finishes, to free the concurrency slot. On refusal release is
// non-nil and safe to call, so callers need no special case.
func (l *Limiter) Acquire(addr net.Addr) (Reason, func()) {
	k := key(addr)
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.evictLocked(now)
	s := l.get(k, now)

	if now.Before(s.blockedTil) {
		return ReasonBlocked, func() {}
	}

	if s.inFlight >= l.cfg.MaxConcurrent {
		return ReasonConcurrent, func() {}
	}

	// Token bucket refill.
	elapsed := now.Sub(s.lastRefill).Seconds()
	if elapsed > 0 {
		s.tokens += elapsed * l.cfg.Rate
		if s.tokens > l.cfg.Burst {
			s.tokens = l.cfg.Burst
		}
		s.lastRefill = now
	}
	if s.tokens < 1 {
		return ReasonRate, func() {}
	}
	s.tokens--
	s.inFlight++

	var once sync.Once
	return Allowed, func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			if cur, ok := l.sources[k]; ok && cur.inFlight > 0 {
				cur.inFlight--
			}
		})
	}
}

// RecordFailure notes a failed authentication. Enough failures inside
// FailureWindow block the source for BlockDuration.
func (l *Limiter) RecordFailure(addr net.Addr) {
	k := key(addr)
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	s := l.get(k, now)

	cutoff := now.Add(-l.cfg.FailureWindow)
	kept := s.failures[:0]
	for _, f := range s.failures {
		if f.After(cutoff) {
			kept = append(kept, f)
		}
	}
	s.failures = append(kept, now)

	if len(s.failures) >= l.cfg.MaxFailures {
		s.blockedTil = now.Add(l.cfg.BlockDuration)
		s.failures = nil
	}
}

// RecordSuccess clears accumulated failures for a source.
func (l *Limiter) RecordSuccess(addr net.Addr) {
	k := key(addr)
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	s := l.get(k, now)
	s.failures = nil
}

// Blocked reports whether a source is currently blocked (for tests/diagnostics).
func (l *Limiter) Blocked(addr net.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	s, ok := l.sources[key(addr)]
	return ok && l.now().Before(s.blockedTil)
}

// evictLocked drops idle sources so memory cannot grow without bound. Sources
// that are blocked or have connections in flight are always retained -- evicting
// a blocked source would reset its penalty. Caller holds mu.
func (l *Limiter) evictLocked(now time.Time) {
	for k, s := range l.sources {
		if s.inFlight > 0 || now.Before(s.blockedTil) {
			continue
		}
		if now.Sub(s.lastSeen) > l.cfg.IdleTTL {
			delete(l.sources, k)
		}
	}
}
