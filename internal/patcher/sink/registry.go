package sink

import (
	"context"
	"fmt"
	"strings"

	"github.com/HarborGuard/harborguard-sensor/internal/scanner"
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

	var cmd string
	var env []string
	if r.credentials != nil && r.credentials.Username != "" {
		cmd = fmt.Sprintf(`skopeo copy --dest-creds "${SKOPEO_DEST_CREDS}" docker-archive:%s docker://%s`, tarPath, dest)
		env = scanner.BuildEnv(map[string]string{
			"SKOPEO_DEST_CREDS": r.credentials.Username + ":" + r.credentials.Password,
		})
	} else {
		cmd = fmt.Sprintf(`skopeo copy docker-archive:%s docker://%s`, tarPath, dest)
	}

	stdout, stderr, err := scanner.ExecWithTimeout(ctx, cmd, 600000, env)
	if err != nil {
		return nil, fmt.Errorf("skopeo copy failed: %w (stderr: %s)", err, trim(stderr))
	}

	digest := parseSkopeoDigest(stdout + stderr)
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
