package scanner

import (
	"context"
	"fmt"
	"os"
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

	_, _, err := ExecWithTimeout(ctx, cmd, trivyTimeoutMs, env)
	durationMs := time.Since(start).Milliseconds()

	if err != nil {
		msg := err.Error()
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
	base := fmt.Sprintf(`trivy image -f json -o "%s"`, outputPath)
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
