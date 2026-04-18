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
	if _, err := exec.LookPath(buildahBinary); err != nil {
		return false, "buildah binary not found on PATH"
	}
	if _, err := exec.LookPath(skopeoBinary); err != nil {
		return false, "skopeo binary not found on PATH"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, buildahBinary, "--version").Run(); err != nil {
		return false, fmt.Sprintf("buildah --version failed: %s", err.Error())
	}

	driver := selectStorageDriver()
	return true, fmt.Sprintf("patch capability enabled (buildah storage-driver=%s)", driver)
}
