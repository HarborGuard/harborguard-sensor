package scanner

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

const dockleTimeoutMs = 180000

type DockleScanner struct{}

func (d *DockleScanner) Name() string { return "dockle" }

func (d *DockleScanner) Scan(ctx context.Context, source types.ImageSource, outputPath string) (*types.ScannerResult, error) {
	start := time.Now()

	if source.Type == "registry" {
		msg := "Dockle does not support direct registry scanning"
		durationMs := time.Since(start).Milliseconds()
		return &types.ScannerResult{Scanner: "dockle", Success: false, Error: msg, DurationMs: durationMs}, nil
	}

	cmd := d.buildCommand(source, outputPath)
	_, _, err := ExecWithTimeout(ctx, cmd, dockleTimeoutMs, nil)
	durationMs := time.Since(start).Milliseconds()

	if err != nil {
		msg := err.Error()
		fmt.Fprintf(os.Stderr, "Dockle scan failed: %s\n", msg)
		_ = WriteFallbackResult(outputPath, msg, nil)
		return &types.ScannerResult{Scanner: "dockle", Success: false, Error: msg, DurationMs: durationMs}, nil
	}

	var data interface{}
	if parseErr := ParseJSONFile(outputPath, &data); parseErr != nil {
		msg := parseErr.Error()
		return &types.ScannerResult{Scanner: "dockle", Success: false, Error: msg, DurationMs: durationMs}, nil
	}

	return &types.ScannerResult{Scanner: "dockle", Success: true, Data: data, DurationMs: durationMs}, nil
}

func (d *DockleScanner) buildCommand(source types.ImageSource, outputPath string) string {
	switch source.Type {
	case "tar":
		return fmt.Sprintf(`dockle --input "%s" --format json --output "%s"`, source.Path, outputPath)
	default:
		return fmt.Sprintf(`dockle --format json --output "%s" "%s"`, outputPath, source.Ref)
	}
}

func (d *DockleScanner) GetVersion() string {
	return GetToolVersion("dockle --version")
}

func (d *DockleScanner) IsAvailable() bool {
	return IsToolAvailable("dockle")
}

func (d *DockleScanner) SupportsSource(source types.ImageSource) bool {
	return source.Type != "registry"
}
