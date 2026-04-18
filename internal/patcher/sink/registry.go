package sink

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

// registrySink pushes the patched image to a container registry via skopeo.
type registrySink struct {
	ref         string
	tag         string
	credentials *types.RegistryCredentials
}

func newRegistrySink(spec types.PatchSinkRegistry, sensorCreds *types.RegistryCredentials) *registrySink {
	creds := spec.Credentials
	if creds == nil {
		creds = sensorCreds
	}
	return &registrySink{ref: spec.Ref, tag: spec.Tag, credentials: creds}
}

func (r *registrySink) Push(ctx context.Context, tarPath string) (*Result, error) {
	if r.tag == "" {
		return nil, fmt.Errorf("registry sink requires an explicit tag")
	}
	dest := fmt.Sprintf("%s:%s", strings.TrimSuffix(r.ref, ":"), r.tag)

	// Invoke skopeo directly via argv — no shell in between. Credentials go
	// as a single literal argument to --dest-creds, avoiding any shell
	// quoting or variable-expansion failure mode.
	args := []string{"copy"}
	if r.credentials != nil && r.credentials.Username != "" {
		args = append(args, "--dest-creds", r.credentials.Username+":"+r.credentials.Password)
	}
	args = append(args, "docker-archive:"+tarPath, "docker://"+dest)

	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(timeoutCtx, "skopeo", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("skopeo copy failed: %w (stderr: %s)", err, trim(stderr.String()))
	}

	digest := parseSkopeoDigest(stdout.String() + stderr.String())
	return &Result{Location: dest, Digest: digest}, nil
}

// parseSkopeoDigest extracts the manifest digest from skopeo output if present.
// skopeo typically writes "Writing manifest to image destination" and a
// digest line when the transport supports it. Returns empty string if not
// found — the caller can HEAD the manifest separately for verification.
func parseSkopeoDigest(output string) string {
	const marker = "sha256:"
	idx := strings.Index(output, marker)
	if idx == -1 {
		return ""
	}
	rest := output[idx:]
	end := len(rest)
	for i, c := range rest {
		if c == '\n' || c == ' ' || c == '\r' || c == ',' || c == ')' {
			end = i
			break
		}
	}
	return rest[:end]
}

func trim(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 500 {
		return s[:500] + "..."
	}
	return s
}
