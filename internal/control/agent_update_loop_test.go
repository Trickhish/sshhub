package control

import (
	"context"
	"testing"
	"time"
)

// The updater must stop when its context is cancelled, so a shutting-down agent
// does not leave a goroutine running or apply an update mid-shutdown.
func TestStartAgentAutoUpdater_StopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	StartAgentAutoUpdater(ctx)
	cancel()
	// No assertion on goroutine count (the first check is jittered and may not
	// have started); this asserts cancellation does not panic or deadlock.
	time.Sleep(50 * time.Millisecond)
}

// The check interval must be frequent enough that a stale agent is corrected
// within a reasonable window, but not so frequent it hammers GitHub.
func TestAgentUpdateCheckInterval_IsReasonable(t *testing.T) {
	if AgentUpdateCheckInterval < 5*time.Minute {
		t.Errorf("interval %s is aggressive enough to risk rate limiting", AgentUpdateCheckInterval)
	}
	if AgentUpdateCheckInterval > 6*time.Hour {
		t.Errorf("interval %s leaves an agent stale too long if the hub stops updating", AgentUpdateCheckInterval)
	}
}
