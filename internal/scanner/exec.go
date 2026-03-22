package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ExecWithTimeout runs a shell command with a timeout and returns stdout/stderr.
func ExecWithTimeout(ctx context.Context, command string, timeoutMs int64, env []string) (string, string, error) {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)
	if len(env) > 0 {
		cmd.Env = env
	} else {
		cmd.Env = os.Environ()
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return stdout.String(), stderr.String(), fmt.Errorf("command timed out after %dms", timeoutMs)
	}
	return stdout.String(), stderr.String(), err
}

// ExecDirect runs a command directly (not via shell) with a timeout.
func ExecDirect(ctx context.Context, binary string, args []string, timeoutMs int64, env []string) (string, string, error) {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary, args...)
	if len(env) > 0 {
		cmd.Env = env
	} else {
		cmd.Env = os.Environ()
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return stdout.String(), stderr.String(), fmt.Errorf("command timed out after %dms", timeoutMs)
	}
	return stdout.String(), stderr.String(), err
}

// ParseJSONFile reads a JSON file and unmarshals it into the provided interface.
func ParseJSONFile(path string, out interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	return json.Unmarshal(data, out)
}

// GetToolVersion runs a version command and returns the first line of output.
func GetToolVersion(command string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	lines := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)
	if len(lines) > 0 {
		return lines[0]
	}
	return "unknown"
}

// IsToolAvailable checks if a binary exists in PATH.
func IsToolAvailable(binary string) bool {
	_, err := exec.LookPath(binary)
	return err == nil
}

// WriteFallbackResult writes a fallback JSON file when a scanner fails.
func WriteFallbackResult(path, errMsg string, extra map[string]interface{}) error {
	data := map[string]interface{}{
		"error": errMsg,
	}
	for k, v := range extra {
		data[k] = v
	}
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}

// FormatSourceRef formats an ImageSource into a scanner-compatible reference string.
func FormatSourceRef(sourceType, ref, path string) string {
	switch sourceType {
	case "docker":
		return "docker:" + ref
	case "registry":
		return "registry:" + ref
	case "tar":
		return "docker-archive:" + path
	default:
		return ref
	}
}

// BuildEnv creates an env slice from os.Environ() plus additional key=value pairs.
func BuildEnv(extra map[string]string) []string {
	env := os.Environ()
	for k, v := range extra {
		env = append(env, k+"="+v)
	}
	return env
}
