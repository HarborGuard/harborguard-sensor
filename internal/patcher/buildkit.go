package patcher

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	buildkitSocketDir = "/run/buildkit"
	buildkitSocket    = "/run/buildkit/buildkitd.sock"
	buildkitBinary    = "buildkitd"
)

// BuildKit supervises a buildkitd process running alongside the sensor.
type BuildKit struct {
	socketURL string
	root      string

	mu   sync.Mutex
	cmd  *exec.Cmd
	done chan struct{}
	exit error
}

// StartBuildKit launches buildkitd and blocks until its socket is ready.
// storageRoot is the directory where buildkit stores layers and snapshots;
// it lives under $WorkDir so the sensor's cleanup sweep catches it.
func StartBuildKit(ctx context.Context, storageRoot string, logOut io.Writer) (*BuildKit, error) {
	if logOut == nil {
		logOut = os.Stderr
	}
	if err := os.MkdirAll(buildkitSocketDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating %s: %w", buildkitSocketDir, err)
	}
	if err := os.MkdirAll(storageRoot, 0o700); err != nil {
		return nil, fmt.Errorf("creating buildkit storage: %w", err)
	}

	args := []string{
		"--addr", "unix://" + buildkitSocket,
		"--root", storageRoot,
		"--oci-worker-snapshotter", selectSnapshotter(),
	}
	if os.Geteuid() != 0 {
		args = append(args, "--oci-worker-no-process-sandbox")
	}

	cmd := exec.Command(buildkitBinary, args...)
	cmd.Stdout = logOut
	cmd.Stderr = logOut
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting buildkitd: %w", err)
	}

	bk := &BuildKit{
		socketURL: "unix://" + buildkitSocket,
		root:      storageRoot,
		cmd:       cmd,
		done:      make(chan struct{}),
	}

	go bk.supervise()

	if err := waitForUnixSocket(ctx, buildkitSocket, 30*time.Second); err != nil {
		_ = bk.Stop()
		return nil, fmt.Errorf("buildkitd socket never came up: %w", err)
	}
	return bk, nil
}

// Addr returns the socket URL for clients like copa.
func (b *BuildKit) Addr() string { return b.socketURL }

// Alive reports whether the daemon is currently running.
func (b *BuildKit) Alive() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	select {
	case <-b.done:
		return false
	default:
		return true
	}
}

// Stop sends SIGTERM, then SIGKILL after a grace period. Idempotent.
func (b *BuildKit) Stop() error {
	b.mu.Lock()
	cmd := b.cmd
	b.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return nil
	}

	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	select {
	case <-b.done:
		return b.exit
	case <-time.After(10 * time.Second):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-b.done
		return b.exit
	}
}

func (b *BuildKit) supervise() {
	err := b.cmd.Wait()
	b.mu.Lock()
	b.exit = err
	close(b.done)
	b.mu.Unlock()
}

// selectSnapshotter picks the buildkit snapshotter based on what the
// kernel/container can actually support.
//
// overlayfs: fastest; needs either native overlay (CAP_SYS_ADMIN) or
//   fuse-overlayfs (+ /dev/fuse) which buildkit selects automatically.
// native: slow fallback that copies layers; always works.
func selectSnapshotter() string {
	if _, err := os.Stat("/dev/fuse"); err == nil {
		return "overlayfs"
	}
	if hasNativeOverlay() {
		return "overlayfs"
	}
	return "native"
}

func hasNativeOverlay() bool {
	data, err := os.ReadFile("/proc/filesystems")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "overlay")
}

// waitForUnixSocket polls until a unix socket accepts a connection.
func waitForUnixSocket(ctx context.Context, path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, err := os.Stat(path); err == nil {
			conn, err := net.DialTimeout("unix", path, 500*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for %s", path)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// BuildKitVersion returns the buildkitd --version string for reporting.
func BuildKitVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, buildkitBinary, "--version").Output()
	if err != nil {
		return "unknown"
	}
	line := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
	return line
}

// DefaultStorageRoot returns the standard storage path under workDir.
func DefaultStorageRoot(workDir string) string {
	return filepath.Join(workDir, "buildkit")
}
