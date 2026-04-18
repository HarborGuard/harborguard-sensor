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
	sourceRef   string
	credentials *types.RegistryCredentials
}

func newRegistrySink(spec types.PatchSinkRegistry, sourceRef string, sensorCreds *types.RegistryCredentials) *registrySink {
	creds := spec.Credentials
	if creds == nil {
		creds = sensorCreds
	}
	return &registrySink{ref: spec.Ref, tag: spec.Tag, sourceRef: sourceRef, credentials: creds}
}

func (r *registrySink) Push(ctx context.Context, tarPath string) (*Result, error) {
	if r.tag == "" {
		return nil, fmt.Errorf("registry sink requires an explicit tag")
	}
	fullRef, err := resolveFullRef(r.ref, r.sourceRef)
	if err != nil {
		return nil, err
	}
	dest := fmt.Sprintf("%s:%s", strings.TrimSuffix(fullRef, ":"), r.tag)

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

// resolveFullRef returns a destination ref that always includes a repository
// path. When the dashboard supplied a full ref (host + repo path), it is
// returned verbatim. When the sink ref is a bare registry host (no "/"), the
// repository path from the source image is appended — otherwise skopeo
// parses "host:tag" as "host:port" and registries reject the push with a
// misleading "invalid credentials" error.
func resolveFullRef(sinkRef, sourceRef string) (string, error) {
	sinkRef = strings.TrimSpace(sinkRef)
	if sinkRef == "" {
		return "", fmt.Errorf("registry sink ref is empty")
	}
	if strings.Contains(sinkRef, "/") {
		return sinkRef, nil
	}
	repo := sourceRepoPath(sourceRef)
	if repo == "" {
		return "", fmt.Errorf("sink ref %q has no repository path and source %q does not supply one", sinkRef, sourceRef)
	}
	return sinkRef + "/" + repo, nil
}

// sourceRepoPath extracts the "/<repo>" portion of a source reference
// (e.g. "572...ecr.../cloud-test/python:tag" → "cloud-test/python"). Returns
// "" when the source itself has no path component.
func sourceRepoPath(sourceRef string) string {
	ref := sourceRef
	if at := strings.LastIndex(ref, "@"); at != -1 {
		ref = ref[:at]
	}
	if colon := strings.LastIndex(ref, ":"); colon != -1 {
		if slash := strings.LastIndex(ref, "/"); colon > slash {
			ref = ref[:colon]
		}
	}
	slash := strings.Index(ref, "/")
	if slash == -1 {
		return ""
	}
	return strings.Trim(ref[slash+1:], "/")
}

func trim(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 500 {
		return s[:500] + "..."
	}
	return s
}
