package scanner

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

const grypeTimeoutMs = 300000

type GrypeScanner struct{}

func (g *GrypeScanner) Name() string { return "grype" }

func (g *GrypeScanner) Scan(source types.ImageSource, outputPath string) (*types.ScannerResult, error) {
	start := time.Now()

	cmd := g.buildCommand(source, outputPath)

	cacheDir := os.Getenv("GRYPE_DB_CACHE_DIR")
	if cacheDir == "" {
		cacheDir = "/workspace/cache/grype"
	}
	env := BuildEnv(map[string]string{"GRYPE_DB_CACHE_DIR": cacheDir})

	_, _, err := ExecWithTimeout(context.Background(), cmd, grypeTimeoutMs, env)
	durationMs := time.Since(start).Milliseconds()

	if err != nil {
		msg := err.Error()
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

func (g *GrypeScanner) SupportsSource(_ types.ImageSource) bool {
	return true
}
