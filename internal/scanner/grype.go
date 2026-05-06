package scanner

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

const grypeTimeoutMs = 300000

type GrypeScanner struct{}

func (g *GrypeScanner) Name() string { return "grype" }

func (g *GrypeScanner) Scan(ctx context.Context, source types.ImageSource, outputPath string) (*types.ScannerResult, error) {
	start := time.Now()

	cmd := g.buildCommand(source, outputPath)

	cacheDir := os.Getenv("GRYPE_DB_CACHE_DIR")
	if cacheDir == "" {
		cacheDir = "/workspace/cache/grype"
	}
	envExtras := map[string]string{"GRYPE_DB_CACHE_DIR": cacheDir}
	if source.Insecure && source.Type == "registry" {
		envExtras["GRYPE_REGISTRY_INSECURE_SKIP_TLS_VERIFY"] = "true"
		envExtras["GRYPE_REGISTRY_INSECURE_USE_HTTP"] = "true"
	}
	env := BuildEnv(envExtras)

	stdout, stderr, err := ExecWithTimeout(ctx, cmd, grypeTimeoutMs, env)
	durationMs := time.Since(start).Milliseconds()

	if err != nil {
		msg := err.Error()
		if s := strings.TrimSpace(stderr); s != "" {
			msg += "\n--- grype stderr ---\n" + s
		}
		if s := strings.TrimSpace(stdout); s != "" {
			msg += "\n--- grype stdout ---\n" + s
		}
		fmt.Fprintf(os.Stderr, "Grype scan failed: %s\n", msg)
		_ = WriteFallbackResult(outputPath, msg, nil)
		return &types.ScannerResult{Scanner: "grype", Success: false, Error: msg, DurationMs: durationMs}, nil
	}

	var data interface{}
	if parseErr := ParseJSONFile(outputPath, &data); parseErr != nil {
		msg := parseErr.Error()
		return &types.ScannerResult{Scanner: "grype", Success: false, Error: msg, DurationMs: durationMs}, nil
	}

	return &types.ScannerResult{Scanner: "grype", Success: true, Data: data, DurationMs: durationMs}, nil
}

func (g *GrypeScanner) buildCommand(source types.ImageSource, outputPath string) string {
	switch source.Type {
	case "docker":
		return fmt.Sprintf(`grype docker:%s -o json > "%s"`, source.Ref, outputPath)
	case "registry":
		return fmt.Sprintf(`grype registry:%s -o json > "%s"`, source.Ref, outputPath)
	case "tar":
		return fmt.Sprintf(`grype docker-archive:%s -o json > "%s"`, source.Path, outputPath)
	default:
		return fmt.Sprintf(`grype docker:%s -o json > "%s"`, source.Ref, outputPath)
	}
}

func (g *GrypeScanner) GetVersion() string {
	return GetToolVersion("grype version")
}

func (g *GrypeScanner) IsAvailable() bool {
	return IsToolAvailable("grype")
}

// SupportsSource declines "registry" so the orchestrator routes grype through
// the skopeo prefetch → tar path used by syft/dockle/dive. Reason: grype's
// `registry:` source uses go-containerregistry, which does not honor ECR's
// auth pattern even when GRYPE_REGISTRY_AUTH_USERNAME/PASSWORD are set with a
// valid `aws ecr get-login-password` token. The May 2026 staging soak showed
// 5/6 organic scans failing with `401 Unauthorized: Not Authorized` from ECR,
// while the same machine's skopeo prefetch (running with the SAME credentials
// from RegistryCreds) succeeded. Routing grype through `docker-archive:`
// against the prefetched tar bypasses the credential issue entirely and
// matches the pattern syft already uses.
//
// "docker" and "tar" sources continue to work as before (grype reads them
// directly without any registry round-trip).
func (g *GrypeScanner) SupportsSource(source types.ImageSource) bool {
	return source.Type != "registry"
}
