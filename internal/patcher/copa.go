package patcher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

const (
	copaBinary       = "copa"
	copaTimeoutMins  = 15
)

// runCopa invokes copa patch, producing an OCI archive at outputPath.
//
// sourceCreds (if non-nil) are written to a temporary docker config.json
// so buildkit can pull the source image. Destination-side auth for the
// patched image is handled by the Sink layer.
func runCopa(ctx context.Context, buildkitAddr, sourceRef, reportPath, outputPath, tag string, sourceCreds *types.RegistryCredentials, logOut *os.File) error {
	if logOut == nil {
		logOut = os.Stderr
	}

	args := []string{
		"patch",
		"--image", sourceRef,
		"--report", reportPath,
		"--output", outputPath,
		"--addr", buildkitAddr,
		"--timeout", fmt.Sprintf("%dm", copaTimeoutMins),
	}
	if tag != "" {
		args = append(args, "--tag", tag)
	}

	env := os.Environ()
	if sourceCreds != nil && sourceCreds.Username != "" {
		dir, err := writeDockerConfig(filepath.Dir(outputPath), sourceRef, *sourceCreds)
		if err != nil {
			return fmt.Errorf("writing docker config: %w", err)
		}
		env = append(env, "DOCKER_CONFIG="+dir)
	}

	copaCtx, cancel := context.WithTimeout(ctx, time.Duration(copaTimeoutMins+2)*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(copaCtx, copaBinary, args...)
	cmd.Env = env
	cmd.Stdout = logOut
	cmd.Stderr = logOut

	if err := cmd.Run(); err != nil {
		if copaCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("copa timed out after %dm", copaTimeoutMins)
		}
		return fmt.Errorf("copa patch: %w", err)
	}
	return nil
}

// writeDockerConfig creates a minimal docker config.json for buildkit/copa
// auth. Returns the directory path to set as DOCKER_CONFIG.
func writeDockerConfig(parentDir, imageRef string, creds types.RegistryCredentials) (string, error) {
	dir := filepath.Join(parentDir, "docker")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	host := registryHostFromRef(imageRef)
	auth := base64.StdEncoding.EncodeToString([]byte(creds.Username + ":" + creds.Password))
	cfg := map[string]interface{}{
		"auths": map[string]interface{}{
			host: map[string]string{
				"auth": auth,
			},
		},
	}
	// Docker Hub historically also keyed by https://index.docker.io/v1/
	if host == "docker.io" || host == "registry-1.docker.io" || host == "index.docker.io" {
		cfg["auths"].(map[string]interface{})["https://index.docker.io/v1/"] = map[string]string{"auth": auth}
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return dir, os.WriteFile(filepath.Join(dir, "config.json"), data, 0o600)
}

// registryHostFromRef extracts the registry host from an image reference.
// Defaults to docker.io if no hostname component is present.
func registryHostFromRef(ref string) string {
	// Strip tag/digest
	if idx := strings.LastIndex(ref, "@"); idx != -1 {
		ref = ref[:idx]
	}
	if idx := strings.LastIndex(ref, ":"); idx != -1 {
		// Don't strip port
		rest := ref[idx+1:]
		if !strings.Contains(rest, "/") && strings.ContainsAny(rest, ".abcdefghijklmnopqrstuvwxyz") &&
			!containsOnlyDigitsAndColon(rest) {
			ref = ref[:idx]
		}
	}
	slash := strings.Index(ref, "/")
	if slash == -1 {
		return "docker.io"
	}
	first := ref[:slash]
	// A hostname has "." or ":" or is "localhost".
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return first
	}
	return "docker.io"
}

func containsOnlyDigitsAndColon(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && c != ':' {
			return false
		}
	}
	return s != ""
}

// CopaVersion runs `copa --version` and returns the first line.
func CopaVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, copaBinary, "--version").Output()
	if err != nil {
		return "unknown"
	}
	return strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
}
