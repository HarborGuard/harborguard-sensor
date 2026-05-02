package scanner

import (
	"context"
	"fmt"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

// Scanner is the interface all scanner implementations must satisfy.
type Scanner interface {
	Name() string
	Scan(ctx context.Context, source types.ImageSource, outputPath string) (*types.ScannerResult, error)
	GetVersion() string
	IsAvailable() bool
	SupportsSource(source types.ImageSource) bool
}

// knownScannerNames is the canonical list of scanner names that
// NewScanner can construct. Kept next to NewScanner so they don't
// drift apart when a scanner is added.
var knownScannerNames = []string{"trivy", "grype", "syft", "dockle", "dive", "osv"}

// KnownScannerNames returns a copy of every scanner name NewScanner
// understands. Callers that pre-warm version caches should use this
// (rather than the operator's enabled-scanners list) so a dashboard-
// dispatched job naming a non-enabled scanner doesn't cache-miss
// inside the per-scan hot path.
func KnownScannerNames() []string {
	out := make([]string, len(knownScannerNames))
	copy(out, knownScannerNames)
	return out
}

// NewScanner creates a scanner instance by name.
func NewScanner(name string) (Scanner, error) {
	switch name {
	case "trivy":
		return &TrivyScanner{}, nil
	case "grype":
		return &GrypeScanner{}, nil
	case "syft":
		return &SyftScanner{}, nil
	case "dockle":
		return &DockleScanner{}, nil
	case "dive":
		return &DiveScanner{}, nil
	case "osv":
		return &OsvScanner{}, nil
	default:
		return nil, fmt.Errorf("Unknown scanner: %s. Valid scanners: trivy, grype, syft, dockle, dive, osv", name)
	}
}

// PartitionBySourceSupport splits scanners into compatible and incompatible groups.
func PartitionBySourceSupport(scanners []Scanner, source types.ImageSource) (compatible, incompatible []Scanner) {
	for _, s := range scanners {
		if s.SupportsSource(source) {
			compatible = append(compatible, s)
		} else {
			incompatible = append(incompatible, s)
		}
	}
	return
}
