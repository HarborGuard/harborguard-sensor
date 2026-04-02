package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
	env := BuildEnv(map[string]string{"SYFT_CACHE_DIR": cacheDir})

	// Main JSON output (retry once on transient failure)
	cmd := fmt.Sprintf(`syft %s -o json > "%s"`, ref, outputPath)
	_, _, err := ExecWithTimeout(ctx, cmd, syftTimeoutMs, env)
	if err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "Syft scan failed, retrying: %s\n", err.Error())
		time.Sleep(2 * time.Second)
		_, _, err = ExecWithTimeout(ctx, cmd, syftTimeoutMs, env)
	}
	if err != nil {
		msg := err.Error()
		if ctx.Err() != nil {
			msg = "scan cancelled"
		}
		fmt.Fprintf(os.Stderr, "Syft scan failed: %s\n", msg)
		_ = WriteFallbackResult(outputPath, msg, nil)
		durationMs := time.Since(start).Milliseconds()
		return &types.ScannerResult{Scanner: "syft", Success: false, Error: msg, DurationMs: durationMs}, nil
	}

	// CycloneDX SBOM (skip if cancelled)
	if ctx.Err() == nil {
		sbomCmd := fmt.Sprintf(`syft %s -o cyclonedx-json@1.5 > "%s"`, ref, sbomPath)
		_, _, err = ExecWithTimeout(ctx, sbomCmd, syftTimeoutMs, env)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Syft SBOM generation failed: %s\n", err.Error())
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

func (s *SyftScanner) SupportsSource(_ types.ImageSource) bool {
	return true
}
