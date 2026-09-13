package control

import (
	"context"
	"fmt"
	"time"
)

// The unprivileged forwarding agent cannot replace executables. Upgrade using
// the local verified installer; the hub has no update-command capability.
func DownloadAndApplyGitHubUpdate(string) error {
	return fmt.Errorf("agent self-update removed: install a verified release locally")
}

const AgentUpdateCheckInterval = 30 * time.Minute

func StartAgentAutoUpdater(context.Context) {}
