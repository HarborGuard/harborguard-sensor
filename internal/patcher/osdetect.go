package patcher

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/HarborGuard/harborguard-sensor/internal/scanner"
)

// DetectOS determines the OS family of a source image, for use as the
// Trivy report's Results[].Type field (which Copa reads to pick a package
// manager). Returns one of the supported families:
// "ubuntu", "debian", "alpine", "centos", "redhat", "fedora", "amazon",
// "oracle", "rocky", "almalinux", "cbl-mariner". Empty string if unknown.
//
// Order of checks:
//  1. Image reference name (e.g., "docker.io/library/ubuntu:22.04").
//  2. skopeo inspect labels (org.opencontainers.image.base.name, etc).
//
// Callers should prefer caller-supplied hints (StrategyHint, PackageManager)
// over this function and fall back here only when those are absent.
func DetectOS(ctx context.Context, imageRef string) (string, error) {
	if fam := osFromName(imageRef); fam != "" {
		return fam, nil
	}
	if fam, err := osFromSkopeoLabels(ctx, imageRef); err == nil && fam != "" {
		return fam, nil
	}
	return "", fmt.Errorf("could not detect OS for %s; supply strategyHint or packageManager on packages", imageRef)
}

// osFromName uses the image reference string as a weak hint.
func osFromName(ref string) string {
	lower := strings.ToLower(ref)
	for keyword, family := range nameHints {
		if strings.Contains(lower, keyword) {
			return family
		}
	}
	return ""
}

var nameHints = map[string]string{
	"ubuntu":    "ubuntu",
	"debian":    "debian",
	"alpine":    "alpine",
	"centos":    "centos",
	"redhat":    "redhat",
	"/rhel":     "redhat",
	"fedora":    "fedora",
	"amazonlinux": "amazon",
	"amzn":      "amazon",
	"oraclelinux": "oracle",
	"rockylinux":  "rocky",
	"almalinux":   "almalinux",
	"mariner":     "cbl-mariner",
}

// osFromSkopeoLabels pulls the image config via skopeo inspect and scans
// well-known labels for a distro identifier.
func osFromSkopeoLabels(ctx context.Context, imageRef string) (string, error) {
	cmd := fmt.Sprintf("skopeo inspect --config docker://%s", imageRef)
	stdout, stderr, err := scanner.ExecWithTimeout(ctx, cmd, 15000, nil)
	if err != nil {
		return "", fmt.Errorf("skopeo inspect: %w (stderr: %s)", err, strings.TrimSpace(stderr))
	}
	var cfg struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
	}
	if err := json.Unmarshal([]byte(stdout), &cfg); err != nil {
		return "", fmt.Errorf("parsing skopeo output: %w", err)
	}
	for key, val := range cfg.Config.Labels {
		lowerKey := strings.ToLower(key)
		lowerVal := strings.ToLower(val)
		if !strings.Contains(lowerKey, "name") && !strings.Contains(lowerKey, "os") && !strings.Contains(lowerKey, "ref") {
			continue
		}
		for keyword, family := range nameHints {
			if strings.Contains(lowerVal, keyword) {
				return family, nil
			}
		}
	}
	return "", nil
}
