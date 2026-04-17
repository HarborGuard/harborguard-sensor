package patcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/HarborGuard/harborguard-sensor/internal/patcher/sink"
	"github.com/HarborGuard/harborguard-sensor/internal/storage"
	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

const sensorVersion = "0.1.0"

// Patcher orchestrates a patch job end-to-end.
type Patcher struct {
	Config              *types.SensorConfig
	BuildKit            *BuildKit
	S3Storage           *storage.S3Storage
	SensorRegistryCreds *types.RegistryCredentials
}

// Execute runs the full patch pipeline and returns an envelope describing
// the outcome. On any error before completion, workDir is cleaned up.
func (p *Patcher) Execute(ctx context.Context, job types.PatchJob) (*types.PatchEnvelope, error) {
	if p.BuildKit == nil || !p.BuildKit.Alive() {
		return nil, fmt.Errorf("buildkit daemon not running")
	}
	if err := validateJob(job); err != nil {
		return nil, err
	}

	startedAt := time.Now().UTC().Format(time.RFC3339)

	workDir := filepath.Join(p.Config.WorkDir, "patches", job.ID)
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating work dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(workDir) }()

	osType, err := p.resolveOSType(ctx, job)
	if err != nil {
		return nil, err
	}

	reportPath := filepath.Join(workDir, "report.json")
	reportBytes, err := BuildTrivyReport(job.Job.Source.Ref, osType, job.Job.Packages)
	if err != nil {
		return nil, fmt.Errorf("building report: %w", err)
	}
	if err := os.WriteFile(reportPath, reportBytes, 0o600); err != nil {
		return nil, fmt.Errorf("writing report: %w", err)
	}

	tag := copaTag(job)
	tarPath := filepath.Join(workDir, "patched.tar")

	fmt.Fprintf(os.Stderr, "[patcher] %s: invoking copa (os=%s, packages=%d)\n",
		job.ID, osType, len(job.Job.Packages))

	if err := runCopa(ctx, p.BuildKit.Addr(), job.Job.Source.Ref, reportPath, tarPath, tag, job.Job.SourceCredentials, nil); err != nil {
		return nil, err
	}

	sinkImpl, err := sink.New(job.Job.Sink, p.S3Storage, p.SensorRegistryCreds)
	if err != nil {
		return nil, fmt.Errorf("resolving sink: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[patcher] %s: shipping to sink kind=%s\n", job.ID, job.Job.Sink.Kind)
	pushResult, err := sinkImpl.Push(ctx, tarPath)
	if err != nil {
		return nil, fmt.Errorf("sink push: %w", err)
	}

	finishedAt := time.Now().UTC().Format(time.RFC3339)

	var sizeBytes int64
	if fi, err := os.Stat(tarPath); err == nil {
		sizeBytes = fi.Size()
	}

	envelope := &types.PatchEnvelope{
		Version: "1.0",
		Sensor: types.EnvelopeSensor{
			ID:      p.Config.SensorID,
			Name:    p.Config.AgentName,
			Version: sensorVersion,
		},
		Source: imageFromRef(job.Job.Source.Ref),
		Patched: types.EnvelopePatchedImage{
			Digest: pushResult.Digest,
			Size:   sizeBytes,
		},
		Patch: types.EnvelopePatch{
			ID:         job.ID,
			StartedAt:  startedAt,
			FinishedAt: finishedAt,
			Status:     "SUCCESS",
		},
		Results: buildPackageResults(job.Job.Packages, "SUCCESS", ""),
		Sink: types.EnvelopePatchSink{
			Kind:     job.Job.Sink.Kind,
			Location: pushResult.Location,
			URL:      pushResult.URL,
		},
		Tooling: map[string]string{
			"buildkit": BuildKitVersion(),
			"copa":     CopaVersion(),
			"runtime":  runtime.GOOS + "/" + runtime.GOARCH,
		},
	}
	return envelope, nil
}

func validateJob(job types.PatchJob) error {
	if job.ID == "" {
		return fmt.Errorf("job.ID required")
	}
	if job.Job.Source.Ref == "" {
		return fmt.Errorf("source.ref required")
	}
	if len(job.Job.Packages) == 0 {
		return fmt.Errorf("packages must be non-empty")
	}
	if job.Job.Sink.Kind == "" {
		return fmt.Errorf("sink.kind required")
	}
	return nil
}

// resolveOSType picks the Trivy Results[].Type string in priority order:
// explicit StrategyHint → PackageManager on packages → name/label detection.
func (p *Patcher) resolveOSType(ctx context.Context, job types.PatchJob) (string, error) {
	if job.Job.StrategyHint != "" && job.Job.StrategyHint != "auto" {
		if os := OSTypeFromPackageManager(job.Job.StrategyHint); os != "" {
			return os, nil
		}
		// strategyHint might itself be an OS family string ("ubuntu", "alpine", ...)
		return job.Job.StrategyHint, nil
	}
	for _, pkg := range job.Job.Packages {
		if os := OSTypeFromPackageManager(pkg.PackageManager); os != "" {
			return os, nil
		}
	}
	return DetectOS(ctx, job.Job.Source.Ref)
}

// copaTag picks the tag copa embeds inside the output oci-archive. When the
// sink is a registry with an explicit tag, reuse it; otherwise derive from
// the source.
func copaTag(job types.PatchJob) string {
	if job.Job.Sink.Kind == "registry" && job.Job.Sink.Registry != nil && job.Job.Sink.Registry.Tag != "" {
		return job.Job.Sink.Registry.Tag
	}
	// Derive <source-tag>-patched
	ref := job.Job.Source.Ref
	at := strings.LastIndex(ref, "@")
	if at != -1 {
		ref = ref[:at]
	}
	colon := strings.LastIndex(ref, ":")
	slash := strings.LastIndex(ref, "/")
	if colon > slash {
		return ref[colon+1:] + "-patched"
	}
	return "patched"
}

func imageFromRef(ref string) types.EnvelopeImage {
	name, tag := splitNameTag(ref)
	return types.EnvelopeImage{Ref: ref, Name: name, Tag: tag}
}

func splitNameTag(ref string) (string, string) {
	at := strings.LastIndex(ref, "@")
	if at != -1 {
		ref = ref[:at]
	}
	colon := strings.LastIndex(ref, ":")
	slash := strings.LastIndex(ref, "/")
	if colon > slash {
		return ref[:colon], ref[colon+1:]
	}
	return ref, ""
}

func buildPackageResults(pkgs []types.PatchPackage, defaultStatus, defaultErr string) []types.PatchPackageResult {
	out := make([]types.PatchPackageResult, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, types.PatchPackageResult{
			Package:        p.Name,
			TargetVersion:  p.TargetVersion,
			PackageManager: p.PackageManager,
			Status:         defaultStatus,
			Error:          defaultErr,
		})
	}
	return out
}
