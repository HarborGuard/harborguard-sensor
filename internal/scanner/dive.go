package scanner

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

const diveTimeoutMs = 240000

type DiveScanner struct{}

func (d *DiveScanner) Name() string { return "dive" }

func (d *DiveScanner) Scan(ctx context.Context, source types.ImageSource, outputPath string) (*types.ScannerResult, error) {
	start := time.Now()

	if source.Type == "registry" {
		msg := "Dive does not support direct registry scanning"
		durationMs := time.Since(start).Milliseconds()
		return &types.ScannerResult{Scanner: "dive", Success: false, Error: msg, DurationMs: durationMs}, nil
	}

	cmd := d.buildCommand(source, outputPath)
	_, _, err := ExecWithTimeout(ctx, cmd, diveTimeoutMs, nil)
	durationMs := time.Since(start).Milliseconds()

	if err != nil {
		msg := err.Error()
		fmt.Fprintf(os.Stderr, "Dive scan failed: %s\n", msg)
		_ = WriteFallbackResult(outputPath, msg, map[string]interface{}{"layer": []interface{}{}})
		return &types.ScannerResult{Scanner: "dive", Success: false, Error: msg, DurationMs: durationMs}, nil
	}

	var data interface{}
	if parseErr := ParseJSONFile(outputPath, &data); parseErr != nil {
		msg := parseErr.Error()
		return &types.ScannerResult{Scanner: "dive", Success: false, Error: msg, DurationMs: durationMs}, nil
	}

	return &types.ScannerResult{Scanner: "dive", Success: true, Data: data, DurationMs: durationMs}, nil
}

func (d *DiveScanner) buildCommand(source types.ImageSource, outputPath string) string {
	switch source.Type {
	case "tar":
		return fmt.Sprintf(`dive --source docker-archive "%s" --json "%s"`, source.Path, outputPath)
	default:
		return fmt.Sprintf(`dive "%s" --json "%s"`, source.Ref, outputPath)
	}
}

func (d *DiveScanner) GetVersion() string {
	return GetToolVersion("dive --version")
}

func (d *DiveScanner) IsAvailable() bool {
	return IsToolAvailable("dive")
}

func (d *DiveScanner) SupportsSource(source types.ImageSource) bool {
	return source.Type != "registry"
}
