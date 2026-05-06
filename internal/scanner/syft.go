package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

const syftTimeoutMs = 300000

type SyftScanner struct{}

func (s *SyftScanner) Name() string { return "syft" }

func (s *SyftScanner) Scan(ctx context.Context, source types.ImageSource, outputPath string) (*types.ScannerResult, error) {
	start := time.Now()

	ref := FormatSourceRef(source.Type, source.Ref, source.Path)
	reportDir := filepath.Dir(outputPath)
	sbomPath := filepath.Join(reportDir, "sbom.cdx.json")

	cacheDir := os.Getenv("SYFT_CACHE_DIR")
	if cacheDir == "" {
		cacheDir = "/workspace/cache/syft"
	}
	envExtras := map[string]string{"SYFT_CACHE_DIR": cacheDir}
	if source.Insecure && source.Type == "registry" {
		envExtras["SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY"] = "true"
		envExtras["SYFT_REGISTRY_INSECURE_USE_HTTP"] = "true"
	}
	env := BuildEnv(envExtras)

	// Main JSON output (retry once on transient failure)
	cmd := fmt.Sprintf(`syft %s -o json > "%s"`, ref, outputPath)
	stdout, stderr, err := ExecWithTimeout(ctx, cmd, syftTimeoutMs, env)
	if err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "Syft scan failed, retrying: %s\n", err.Error())
		time.Sleep(2 * time.Second)
		stdout, stderr, err = ExecWithTimeout(ctx, cmd, syftTimeoutMs, env)
	}
	if err != nil {
		msg := err.Error()
		if ctx.Err() != nil {
			msg = "scan cancelled"
		} else {
			if s := strings.TrimSpace(stderr); s != "" {
				msg += "\n--- syft stderr ---\n" + s
			}
			if s := strings.TrimSpace(stdout); s != "" {
				msg += "\n--- syft stdout ---\n" + s
			}
		}
		fmt.Fprintf(os.Stderr, "Syft scan failed: %s\n", msg)
		_ = WriteFallbackResult(outputPath, msg, nil)
		durationMs := time.Since(start).Milliseconds()
		return &types.ScannerResult{Scanner: "syft", Success: false, Error: msg, DurationMs: durationMs}, nil
	}

	// CycloneDX SBOM (skip if cancelled)
	if ctx.Err() == nil {
		sbomCmd := fmt.Sprintf(`syft %s -o cyclonedx-json@1.5 > "%s"`, ref, sbomPath)
		sbomStdout, sbomStderr, sbomErr := ExecWithTimeout(ctx, sbomCmd, syftTimeoutMs, env)
		if sbomErr != nil {
			msg := sbomErr.Error()
			if s := strings.TrimSpace(sbomStderr); s != "" {
				msg += "\n--- syft sbom stderr ---\n" + s
			}
			if s := strings.TrimSpace(sbomStdout); s != "" {
				msg += "\n--- syft sbom stdout ---\n" + s
			}
			fmt.Fprintf(os.Stderr, "Syft SBOM generation failed: %s\n", msg)
		}
	}

	var data interface{}
	if parseErr := ParseJSONFile(outputPath, &data); parseErr != nil {
		msg := parseErr.Error()
		durationMs := time.Since(start).Milliseconds()
		return &types.ScannerResult{Scanner: "syft", Success: false, Error: msg, DurationMs: durationMs}, nil
	}

	durationMs := time.Since(start).Milliseconds()
	return &types.ScannerResult{Scanner: "syft", Success: true, Data: data, DurationMs: durationMs}, nil
}

func (s *SyftScanner) GetVersion() string {
	return GetToolVersion("syft version")
}

func (s *SyftScanner) IsAvailable() bool {
	return IsToolAvailable("syft")
}

// SupportsSource declines "registry" so the orchestrator routes syft through
// the skopeo prefetch → tar path used by dive. This consolidates all
// registry auth into a single skopeo invocation (which reads
// REGISTRY_USER/REGISTRY_PASS or the agent-populated RegistryCreds map) and
// avoids syft needing its own SYFT_REGISTRY_AUTH_* env vars that CLI
// dispatchers historically didn't set.
func (s *SyftScanner) SupportsSource(source types.ImageSource) bool {
	return source.Type != "registry"
}
