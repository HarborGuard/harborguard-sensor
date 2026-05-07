package scanner

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

const trivyTimeoutMs = 300000

type TrivyScanner struct{}

func (t *TrivyScanner) Name() string { return "trivy" }

func (t *TrivyScanner) Scan(ctx context.Context, source types.ImageSource, outputPath string) (*types.ScannerResult, error) {
	start := time.Now()

	cmd := t.buildCommand(source, outputPath)

	cacheDir := os.Getenv("TRIVY_CACHE_DIR")
	if cacheDir == "" {
		cacheDir = "/workspace/cache/trivy"
	}
	env := BuildEnv(map[string]string{"TRIVY_CACHE_DIR": cacheDir})

	stdout, stderr, err := ExecWithTimeout(ctx, cmd, trivyTimeoutMs, env)
	durationMs := time.Since(start).Milliseconds()

	if err != nil {
		msg := err.Error()
		if s := strings.TrimSpace(stderr); s != "" {
			msg += "\n--- trivy stderr ---\n" + s
		}
		if s := strings.TrimSpace(stdout); s != "" {
			msg += "\n--- trivy stdout ---\n" + s
		}
		fmt.Fprintf(os.Stderr, "Trivy scan failed: %s\n", msg)
		_ = WriteFallbackResult(outputPath, msg, nil)
		return &types.ScannerResult{Scanner: "trivy", Success: false, Error: msg, DurationMs: durationMs}, nil
	}

	var data interface{}
	if parseErr := ParseJSONFile(outputPath, &data); parseErr != nil {
		msg := parseErr.Error()
		return &types.ScannerResult{Scanner: "trivy", Success: false, Error: msg, DurationMs: durationMs}, nil
	}

	return &types.ScannerResult{Scanner: "trivy", Success: true, Data: data, DurationMs: durationMs}, nil
}

func (t *TrivyScanner) buildCommand(source types.ImageSource, outputPath string) string {
	// --cache-backend memory bypasses fanal.db (the per-image artifact cache)
	// entirely. Trivy's default fs backend opens <TRIVY_CACHE_DIR>/fanal/fanal.db
	// O_RDWR|O_CREAT, which fails on read-only NFS-baked DB layouts. The
	// vulnerability DB itself (trivy.db) is unaffected — it stays RDONLY.
	// Verified against trivy v0.69.3: scan output is byte-identical to fs
	// backend, only the per-image artifact cache becomes throwaway (which is
	// fine in our ephemeral-machine-per-scan topology).
	base := fmt.Sprintf(`trivy image --cache-backend memory -f json -o "%s"`, outputPath)
	if source.Insecure && source.Type == "registry" {
		base += " --insecure"
	}
	switch source.Type {
	case "tar":
		return fmt.Sprintf(`%s --input "%s"`, base, source.Path)
	default:
		return fmt.Sprintf(`%s "%s"`, base, source.Ref)
	}
}

func (t *TrivyScanner) GetVersion() string {
	return GetToolVersion("trivy --version")
}

func (t *TrivyScanner) IsAvailable() bool {
	return IsToolAvailable("trivy")
}

func (t *TrivyScanner) SupportsSource(_ types.ImageSource) bool {
	return true
}
