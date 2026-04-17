package patcher

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// Probe checks whether this sensor can run patch jobs. Returns a boolean and
// a human-readable reason for the decision. The reason should be logged at
// startup so operators can see why patching was enabled or disabled.
func Probe() (bool, string) {
	if _, err := exec.LookPath(buildkitBinary); err != nil {
		return false, "buildkitd binary not found on PATH"
	}
	if _, err := exec.LookPath(copaBinary); err != nil {
		return false, "copa binary not found on PATH"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, buildkitBinary, "--version").Run(); err != nil {
		return false, fmt.Sprintf("buildkitd --version failed: %s", err.Error())
	}
	if err := exec.CommandContext(ctx, copaBinary, "--version").Run(); err != nil {
		return false, fmt.Sprintf("copa --version failed: %s", err.Error())
	}

	snap := selectSnapshotter()
	return true, fmt.Sprintf("patch capability enabled (buildkit snapshotter=%s)", snap)
}
