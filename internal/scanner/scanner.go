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
