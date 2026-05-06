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

const osvTimeoutMs = 300000

type OsvScanner struct{}

func (o *OsvScanner) Name() string { return "osv" }

func (o *OsvScanner) Scan(ctx context.Context, source types.ImageSource, outputPath string) (*types.ScannerResult, error) {
	start := time.Now()

	reportDir := filepath.Dir(outputPath)
	ownSbom := filepath.Join(reportDir, "osv-sbom.cdx.json")
	cleanupSbom := true

	// Try to reuse Syft's SBOM if available
	syftSbom := filepath.Join(reportDir, "sbom.cdx.json")
	if _, err := os.Stat(syftSbom); err == nil {
		// Copy the existing SBOM
		data, readErr := os.ReadFile(syftSbom)
		if readErr == nil {
			_ = os.WriteFile(ownSbom, data, 0644)
		}
	} else {
		// Generate independent SBOM
		ref := FormatSourceRef(source.Type, source.Ref, source.Path)
		cmd := fmt.Sprintf(`syft %s -o cyclonedx-json@1.5 > "%s"`, ref, ownSbom)
		var sbomEnv []string
		if source.Insecure && source.Type == "registry" {
			sbomEnv = BuildEnv(map[string]string{
				"SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY": "true",
				"SYFT_REGISTRY_INSECURE_USE_HTTP":        "true",
			})
		}
		stdout, stderr, err := ExecWithTimeout(ctx, cmd, osvTimeoutMs, sbomEnv)
		if err != nil {
			msg := err.Error()
			if ctx.Err() != nil {
				msg = "scan cancelled"
			} else {
				if s := strings.TrimSpace(stderr); s != "" {
					msg += "\n--- syft (osv sbom) stderr ---\n" + s
				}
				if s := strings.TrimSpace(stdout); s != "" {
					msg += "\n--- syft (osv sbom) stdout ---\n" + s
				}
			}
			fmt.Fprintf(os.Stderr, "OSV scan failed: %s\n", msg)
			_ = WriteFallbackResult(outputPath, msg, map[string]interface{}{"vulnerabilities": []interface{}{}})
			durationMs := time.Since(start).Milliseconds()
			return &types.ScannerResult{Scanner: "osv", Success: false, Error: msg, DurationMs: durationMs}, nil
		}
	}

	// Run osv-scanner — exit code 1 means vulns found (success)
	cmd := fmt.Sprintf(`osv-scanner -L "%s" --verbosity error --format json > "%s"`, ownSbom, outputPath)
	stdout, stderr, err := ExecWithTimeout(ctx, cmd, osvTimeoutMs, nil)

	if err != nil {
		// Check if output file was written (exit code 1 = vulns found)
		if _, statErr := os.Stat(outputPath); statErr != nil {
			msg := err.Error()
			if s := strings.TrimSpace(stderr); s != "" {
				msg += "\n--- osv-scanner stderr ---\n" + s
			}
			if s := strings.TrimSpace(stdout); s != "" {
				msg += "\n--- osv-scanner stdout ---\n" + s
			}
			fmt.Fprintf(os.Stderr, "OSV scan failed: %s\n", msg)
			_ = WriteFallbackResult(outputPath, msg, map[string]interface{}{"vulnerabilities": []interface{}{}})
			if cleanupSbom {
				_ = os.Remove(ownSbom)
			}
			durationMs := time.Since(start).Milliseconds()
			return &types.ScannerResult{Scanner: "osv", Success: false, Error: msg, DurationMs: durationMs}, nil
		}
		// Output exists — vulns found is success
	}

	if cleanupSbom {
		_ = os.Remove(ownSbom)
	}

	var data interface{}
	if parseErr := ParseJSONFile(outputPath, &data); parseErr != nil {
		msg := parseErr.Error()
		durationMs := time.Since(start).Milliseconds()
		return &types.ScannerResult{Scanner: "osv", Success: false, Error: msg, DurationMs: durationMs}, nil
	}

	durationMs := time.Since(start).Milliseconds()
	return &types.ScannerResult{Scanner: "osv", Success: true, Data: data, DurationMs: durationMs}, nil
}

func (o *OsvScanner) GetVersion() string {
	return GetToolVersion("osv-scanner --version")
}

func (o *OsvScanner) IsAvailable() bool {
	return IsToolAvailable("osv-scanner")
}

// SupportsSource declines "registry" so the orchestrator routes osv (and the
// internal syft SBOM-generation step) through the skopeo prefetch → tar
// path. Reason: when the source is registry, osv's syft fallback hits the
// registry directly with go-containerregistry — which does not honor ECR
// auth even when SYFT_REGISTRY_AUTH_USERNAME/PASSWORD are set (same root
// cause as the grype regression observed in the May 2026 staging soak: 6/6
// osv scans failed with `401 Unauthorized: Not Authorized`).
//
// Routing osv through the tar makes its internal syft call use
// `docker-archive:` source (no registry round-trip, no credential plumbing
// required). Reuse of the main syft scanner's `sbom.cdx.json` continues to
// work — both run in the incompatible batch concurrently against the same
// tar; if syft writes its SBOM first osv reuses it, otherwise osv generates
// its own from the tar (same operation, just duplicated).
func (o *OsvScanner) SupportsSource(source types.ImageSource) bool {
	return source.Type != "registry"
}
