package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/HarborGuard/harborguard-sensor/internal/config"
	"github.com/HarborGuard/harborguard-sensor/internal/patcher"
	"github.com/HarborGuard/harborguard-sensor/internal/scanner"
	"github.com/HarborGuard/harborguard-sensor/internal/storage"
	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

const patchSensorVersion = "0.1.0"

var patchCmd = &cobra.Command{
	Use:   "patch <sourceImageRef>",
	Short: "One-shot patch of a container image",
	Long: `Pulls the named container image, upgrades the supplied list of
packages via buildah, commits the result, and pushes the patched
image to the configured sink (registry, S3, or presigned URL).

Intended for ephemeral Fly Machine invocations: the dashboard
dispatches a single machine to run "harborguard-sensor patch", the
machine pulls + patches + pushes + reports back to --upload-result-url,
then exits. No agent registration, no polling.

Two registries are involved: the SOURCE registry (where the unpatched
image is pulled from — credentials via REGISTRY_USER/REGISTRY_PASS env)
and the SINK registry (where the patched image is pushed — credentials
via SINK_REGISTRY_USER/SINK_REGISTRY_PASS env, or --sink-username /
--sink-password flags).`,
	Args: cobra.ExactArgs(1),
	RunE: runPatch,
}

func init() {
	patchCmd.Flags().String("patch-id", "", "Dashboard patch_operation row ID (required)")
	patchCmd.Flags().String("upload-result-url", "", "URL to POST the patch result envelope (required) — typically the dashboard's /api/patches/upload")
	patchCmd.Flags().String("api-key", "", "Bearer token for the result POST (required)")

	// Source. Source image ref comes from positional arg; insecure flag
	// is derived from the ref's scheme but can also be forced here.
	patchCmd.Flags().Bool("source-insecure", false, "Pull source over plain http / skip TLS verification (set automatically if the imageRef carries http://)")

	// Packages: a JSON array. Encoding []PatchPackage as flags would
	// require either repeated --package-name / --package-version /
	// --package-manager triples (fragile to align across the trio) or
	// a custom delimiter format. JSON is what the dashboard already
	// has on hand — patches are dispatched with the same shape — so
	// this avoids a second encoding the dashboard would have to learn.
	patchCmd.Flags().String("packages-json", "", `JSON array of {name,targetVersion,packageManager?} objects (required). Example: '[{"name":"openssl","targetVersion":"3.0.2-0ubuntu1.10"}]'`)
	patchCmd.Flags().String("strategy-hint", "auto", "Patching strategy: auto | apt | apk | yum | dnf")
	patchCmd.Flags().Bool("preserve-config", false, "Preserve image config (entrypoint/cmd/env) from the source")

	// Sink — registry-only via flags. S3 and presigned sinks are still
	// reachable by passing --sink-spec-json with a full PatchSink JSON
	// blob; this keeps the simple registry case ergonomic without
	// closing the door on the other two kinds.
	patchCmd.Flags().String("sink-kind", "registry", "Sink kind: registry | s3 | presigned")
	patchCmd.Flags().String("sink-ref", "", "Destination registry repo (e.g. registry.example.com/app) — required when --sink-kind=registry")
	patchCmd.Flags().String("sink-tag", "", "Destination tag — required when --sink-kind=registry")
	patchCmd.Flags().String("sink-username", "", "Sink registry username (env: SINK_REGISTRY_USER)")
	patchCmd.Flags().String("sink-password", "", "Sink registry password (env: SINK_REGISTRY_PASS)")
	patchCmd.Flags().Bool("sink-insecure", false, "Push to sink over plain http / skip TLS verification")
	patchCmd.Flags().String("sink-spec-json", "", "Full PatchSink JSON; overrides all --sink-* flags. Use this for s3/presigned sinks.")
}

// patchExecuteFn is the package-level seam for unit tests. Same
// rationale as exportExecuteFn — production points at the real
// patcher; tests swap in a stub so they don't need buildah or skopeo
// to run.
//
// NOTE: this is a package-global mutated by withStubPatchExecute.
// Tests that touch it MUST NOT call t.Parallel() — sibling tests in
// the same package would race on the swap.
var patchExecuteFn = func(ctx context.Context, p *patcher.Patcher, job types.PatchJob) (*types.PatchEnvelope, error) {
	return p.Execute(ctx, job)
}

func runPatch(cmd *cobra.Command, args []string) error {
	sourceRef := args[0]

	patchID, _ := cmd.Flags().GetString("patch-id")
	uploadResultURL, _ := cmd.Flags().GetString("upload-result-url")
	apiKey, _ := cmd.Flags().GetString("api-key")
	sourceInsecure, _ := cmd.Flags().GetBool("source-insecure")
	packagesJSON, _ := cmd.Flags().GetString("packages-json")
	strategyHint, _ := cmd.Flags().GetString("strategy-hint")
	preserveConfig, _ := cmd.Flags().GetBool("preserve-config")
	sinkKind, _ := cmd.Flags().GetString("sink-kind")
	sinkRef, _ := cmd.Flags().GetString("sink-ref")
	sinkTag, _ := cmd.Flags().GetString("sink-tag")
	sinkUsername, _ := cmd.Flags().GetString("sink-username")
	sinkPassword, _ := cmd.Flags().GetString("sink-password")
	sinkInsecure, _ := cmd.Flags().GetBool("sink-insecure")
	sinkSpecJSON, _ := cmd.Flags().GetString("sink-spec-json")

	if missing := requiredMissing(map[string]string{
		"--patch-id":          patchID,
		"--upload-result-url": uploadResultURL,
		"--api-key":           apiKey,
		"--packages-json":     packagesJSON,
	}); len(missing) > 0 {
		return fmt.Errorf("missing required flags: %s", strings.Join(missing, ", "))
	}

	// Sink credentials env-fallback. Mirrors the source credentials
	// fallback below — flag wins, env fills the gap. The split env-var
	// pair (SINK_REGISTRY_USER vs REGISTRY_USER) lets a Fly Machine
	// dispatch be configured with two distinct registries cleanly:
	// patches commonly read from a public source (no creds) and write
	// to a private sink, or vice versa. Using a single REGISTRY_USER
	// for both would conflate the two.
	if sinkUsername == "" {
		sinkUsername = os.Getenv("SINK_REGISTRY_USER")
	}
	if sinkPassword == "" {
		sinkPassword = os.Getenv("SINK_REGISTRY_PASS")
	}

	var packages []types.PatchPackage
	if err := json.Unmarshal([]byte(packagesJSON), &packages); err != nil {
		return fmt.Errorf("parsing --packages-json: %w", err)
	}
	if len(packages) == 0 {
		return fmt.Errorf("--packages-json must be a non-empty JSON array")
	}

	cfg, err := config.LoadConfig(map[string]string{
		"apiKey": apiKey,
	})
	if err != nil {
		return err
	}

	// Source ref normalization mirrors agent-mode processPatchJob.
	normalizedSourceRef, schemeWasHTTP, _ := scanner.NormalizeImageRef(sourceRef)
	insecure := sourceInsecure || schemeWasHTTP

	// Source creds: REGISTRY_USER / REGISTRY_PASS, same as scan/export
	// flow. PatchJob's SourceCredentials field (when populated) wins
	// over SensorRegistryCreds inside Execute, and we want the env-
	// supplied creds to be authoritative for the source pull.
	var sourceCreds *types.RegistryCredentials
	if user := os.Getenv("REGISTRY_USER"); user != "" {
		sourceCreds = &types.RegistryCredentials{
			Username: user,
			Password: os.Getenv("REGISTRY_PASS"),
		}
	}

	sink, err := buildPatchSink(sinkSpecJSON, sinkKind, sinkRef, sinkTag, sinkUsername, sinkPassword, sinkInsecure)
	if err != nil {
		return fmt.Errorf("building sink: %w", err)
	}

	job := types.PatchJob{
		ID: patchID,
		Job: types.AgentJobPatch{
			Source: types.ImageSource{
				Type:     "registry",
				Ref:      normalizedSourceRef,
				Insecure: insecure,
			},
			SourceCredentials: sourceCreds,
			Packages:          packages,
			StrategyHint:      strategyHint,
			Sink:              sink,
			PreserveConfig:    preserveConfig,
		},
	}

	// SensorRegistryCreds is the sink-side credential fallback for the
	// patch package — it's used by the registry sink when the job
	// doesn't supply per-job creds. We use the SINK_REGISTRY_USER pair
	// here intentionally: the source-side creds (REGISTRY_USER) are
	// already wired through job.SourceCredentials above, so this
	// position is now free to feed the sink path.
	var sensorSinkCreds *types.RegistryCredentials
	if sinkUsername != "" {
		sensorSinkCreds = &types.RegistryCredentials{
			Username: sinkUsername,
			Password: sinkPassword,
		}
	}

	// Initialize S3 storage so non-registry sinks (s3 / presigned)
	// dispatched via --sink-spec-json can actually push. Mirrors
	// scan.go's gating: build only when bucket+access+secret are all
	// set; on NewS3Storage error, fail loudly when the resolved sink
	// requires it (s3/presigned), silently fall back to nil otherwise
	// so registry sinks still work for operators who never configured
	// S3. sink.New only touches S3Storage when spec.Kind == "s3" or
	// "presigned" (see internal/patcher/sink/sink.go), so a nil here
	// is safe for the registry case.
	var s3store *storage.S3Storage
	if cfg.S3Bucket != "" && cfg.S3AccessKey != "" && cfg.S3SecretKey != "" {
		var s3err error
		s3store, s3err = storage.NewS3Storage(types.S3Config{
			Endpoint:  cfg.S3Endpoint,
			Bucket:    cfg.S3Bucket,
			AccessKey: cfg.S3AccessKey,
			SecretKey: cfg.S3SecretKey,
			Region:    cfg.S3Region,
		})
		if s3err != nil {
			if sink.Kind == "s3" || sink.Kind == "presigned" {
				return fmt.Errorf("sink kind %q requires valid S3 configuration: %w", sink.Kind, s3err)
			}
			fmt.Fprintf(os.Stderr, "[patch] S3 storage init failed (%s); registry sinks unaffected\n", s3err.Error())
			s3store = nil
		}
	} else if sink.Kind == "s3" || sink.Kind == "presigned" {
		return fmt.Errorf("sink kind %q requires S3 configuration (HG_S3_BUCKET, HG_S3_ACCESS_KEY/AWS_ACCESS_KEY_ID, HG_S3_SECRET_KEY/AWS_SECRET_ACCESS_KEY)", sink.Kind)
	}

	p := &patcher.Patcher{
		Config:              cfg,
		S3Storage:           s3store,
		SensorRegistryCreds: sensorSinkCreds,
	}

	ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	fmt.Fprintf(os.Stderr, "[patch] %s: starting (source=%s, sink=%s, packages=%d)\n",
		patchID, normalizedSourceRef, sink.Kind, len(packages))

	envelope, execErr := patchExecuteFn(ctx, p, job)
	if execErr != nil {
		fmt.Fprintf(os.Stderr, "[patch] %s: failed: %s\n", patchID, execErr.Error())
		failedEnvelope := buildFailedPatchEnvelope(cfg, patchID, normalizedSourceRef, packages, sink, execErr)
		if postErr := postResultEnvelope(ctx, uploadResultURL, apiKey, failedEnvelope); postErr != nil {
			fmt.Fprintf(os.Stderr, "[patch] %s: failure-envelope POST also failed: %s\n", patchID, postErr.Error())
		}
		return fmt.Errorf("patch failed: %w", execErr)
	}

	fmt.Fprintf(os.Stderr, "[patch] %s: posting result envelope (sink=%s, location=%s)\n",
		patchID, envelope.Sink.Kind, envelope.Sink.Location)

	if err := postResultEnvelope(ctx, uploadResultURL, apiKey, envelope); err != nil {
		fmt.Fprintf(os.Stderr, "[patch] %s: result POST failed: %s\n", patchID, err.Error())
		return fmt.Errorf("posting result envelope: %w", err)
	}

	// Patch.Status carries SUCCESS | PARTIAL | FAILED. A FAILED status
	// from buildah (every package install failed) shouldn't return zero
	// — match agent-mode's processPatchJob, which flips ReportJobStatus
	// to "failed" in that case. Fly Machine supervisors look at exit
	// codes, so returning success here would mask a fully-failed patch.
	if envelope.Patch.Status == "FAILED" {
		return fmt.Errorf("all packages failed to install (see result entries)")
	}
	fmt.Fprintf(os.Stderr, "[patch] %s: complete (status=%s)\n", patchID, envelope.Patch.Status)
	return nil
}

// buildPatchSink turns the sink-related flags into a PatchSink struct.
// When --sink-spec-json is non-empty it takes precedence — useful for
// s3 / presigned sinks where the structured fields don't have
// dedicated flags. Otherwise we build a registry sink from the
// individual flags (the only kind we expose first-class flags for).
func buildPatchSink(specJSON, kind, ref, tag, username, password string, insecure bool) (types.PatchSink, error) {
	if specJSON != "" {
		var sink types.PatchSink
		if err := json.Unmarshal([]byte(specJSON), &sink); err != nil {
			return types.PatchSink{}, fmt.Errorf("parsing --sink-spec-json: %w", err)
		}
		if sink.Kind == "" {
			return types.PatchSink{}, fmt.Errorf("--sink-spec-json missing required field 'kind'")
		}
		return sink, nil
	}

	switch kind {
	case "registry":
		if ref == "" || tag == "" {
			return types.PatchSink{}, fmt.Errorf("--sink-ref and --sink-tag are required when --sink-kind=registry")
		}
		// Mirror agent-mode normalization: scheme-prefixed sink refs
		// reach skopeo as "docker://http://..." and fail. Stripping
		// here keeps the failure surface small for direct-CLI use.
		normalizedRef, schemeWasHTTP, _ := scanner.NormalizeImageRef(ref)
		var creds *types.RegistryCredentials
		if username != "" {
			creds = &types.RegistryCredentials{Username: username, Password: password}
		}
		return types.PatchSink{
			Kind: "registry",
			Registry: &types.PatchSinkRegistry{
				Ref:         normalizedRef,
				Tag:         tag,
				Credentials: creds,
				Insecure:    insecure || schemeWasHTTP,
			},
		}, nil
	case "s3", "presigned":
		// Without --sink-spec-json there are no individual flags for
		// the structured S3 fields (bucket, keyPrefix, ttl). The user
		// has to use --sink-spec-json. Surfacing this explicitly
		// rather than silently building an empty sink lets the
		// operator know they hit a flag-coverage gap, not a bug.
		return types.PatchSink{}, fmt.Errorf("--sink-kind=%s requires --sink-spec-json (no individual flags exposed for s3/presigned fields)", kind)
	default:
		return types.PatchSink{}, fmt.Errorf("unknown --sink-kind: %q", kind)
	}
}

// buildFailedPatchEnvelope synthesizes a PatchEnvelope with
// Patch.Status="FAILED" and per-package FAILED entries so the
// dashboard's /api/patches/upload route can flip the patch row to
// FAILED in-band. Reasoning matches buildFailedExportEnvelope: the
// one-shot path can't use /api/agent/jobs/{id}/status and a single
// envelope POST keeps the dashboard surface unchanged.
//
// Per-package status is FAILED, not SKIPPED: the dashboard surfaces
// the buildah cause via `envelope.results.find(r => r.status === "FAILED")`
// (see patch-operations.ts). With SKIPPED the dashboard fell back to
// the literal string "Patch failed" — losing the actual error.
//
// Patched is populated with explicit zero values rather than left as
// the struct's empty {} because EnvelopePatchedImage.Size has dropped
// its omitempty tag. The dashboard does BigInt(envelope.patched.sizeBytes),
// which throws for undefined; serializing 0 keeps the contract intact.
func buildFailedPatchEnvelope(cfg *types.SensorConfig, patchID, sourceRef string, packages []types.PatchPackage, sink types.PatchSink, execErr error) *types.PatchEnvelope {
	now := time.Now().UTC().Format(time.RFC3339)
	name, tag := splitImageNameTag(sourceRef)

	results := make([]types.PatchPackageResult, 0, len(packages))
	for _, pkg := range packages {
		results = append(results, types.PatchPackageResult{
			Package:        pkg.Name,
			TargetVersion:  pkg.TargetVersion,
			PackageManager: pkg.PackageManager,
			Status:         "FAILED",
			Error:          execErr.Error(),
		})
	}

	return &types.PatchEnvelope{
		Version: "1.0",
		Sensor: types.EnvelopeSensor{
			ID:      cfg.SensorID,
			Name:    cfg.AgentName,
			Version: patchSensorVersion,
		},
		Source: types.EnvelopeImage{
			Ref:  sourceRef,
			Name: name,
			Tag:  tag,
		},
		// Defensive zero values: Digest stays empty (omitempty trims it
		// from the wire), Size stays 0 and serializes explicitly because
		// the dashboard's BigInt() call requires the field to be present.
		Patched: types.EnvelopePatchedImage{
			Digest: "",
			Size:   0,
		},
		Patch: types.EnvelopePatch{
			ID:         patchID,
			StartedAt:  now,
			FinishedAt: now,
			Status:     "FAILED",
		},
		Results: results,
		Sink: types.EnvelopePatchSink{
			Kind: sink.Kind,
		},
		Tooling: map[string]string{
			"runtime": runtime.GOOS + "/" + runtime.GOARCH,
			"error":   execErr.Error(),
		},
	}
}
