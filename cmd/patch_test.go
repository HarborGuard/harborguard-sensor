package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/pflag"

	"github.com/HarborGuard/harborguard-sensor/internal/patcher"
	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

// withStubPatchExecute mirrors withStubExportExecute. Same rationale:
// production points at patcher.Patcher.Execute; tests swap in a stub
// so they don't need buildah or skopeo.
func withStubPatchExecute(t *testing.T, stub func(ctx context.Context, p *patcher.Patcher, job types.PatchJob) (*types.PatchEnvelope, error)) {
	t.Helper()
	orig := patchExecuteFn
	patchExecuteFn = stub
	t.Cleanup(func() { patchExecuteFn = orig })
}

// resetPatchFlags is the patch-side equivalent of resetExportFlags.
// Same reason: pflag values stick between rootCmd.Execute() calls in
// the same process.
func resetPatchFlags(t *testing.T) {
	t.Helper()
	patchCmd.Flags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
	})
}

func TestRunPatchSuccess(t *testing.T) {
	srv, rec := newRecorderServer(t)

	withEnv(t, "REGISTRY_USER", "src-user")
	withEnv(t, "REGISTRY_PASS", "src-pass")
	withEnv(t, "SINK_REGISTRY_USER", "sink-user")
	withEnv(t, "SINK_REGISTRY_PASS", "sink-pass")

	var capturedJob types.PatchJob
	withStubPatchExecute(t, func(ctx context.Context, p *patcher.Patcher, job types.PatchJob) (*types.PatchEnvelope, error) {
		capturedJob = job
		return &types.PatchEnvelope{
			Version: "1.0",
			Sensor:  types.EnvelopeSensor{Version: "0.1.0"},
			Source:  types.EnvelopeImage{Ref: job.Job.Source.Ref, Name: "alpine", Tag: "3.18"},
			Patched: types.EnvelopePatchedImage{Digest: "sha256:abc", Size: 999},
			Patch: types.EnvelopePatch{
				ID:     job.ID,
				Status: "SUCCESS",
			},
			Results: []types.PatchPackageResult{
				{Package: "openssl", TargetVersion: "3.0.2-0ubuntu1.10", Status: "SUCCESS"},
			},
			Sink: types.EnvelopePatchSink{
				Kind:     "registry",
				Location: "registry.example.com/app:patched",
			},
			Tooling: map[string]string{"buildah": "1.30.0"},
		}, nil
	})

	resetPatchFlags(t)
	rootCmd.SetArgs([]string{
		"patch",
		"alpine:3.18",
		"--patch-id", "patch-1",
		"--upload-result-url", srv.URL,
		"--api-key", "k",
		"--packages-json", `[{"name":"openssl","targetVersion":"3.0.2-0ubuntu1.10","packageManager":"apt"}]`,
		"--sink-kind", "registry",
		"--sink-ref", "registry.example.com/app",
		"--sink-tag", "patched",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if rec.hits.Load() != 1 {
		t.Fatalf("recorder hits = %d, want 1", rec.hits.Load())
	}
	if rec.method != http.MethodPost {
		t.Errorf("method = %q", rec.method)
	}
	if rec.authHeader != "Bearer k" {
		t.Errorf("auth = %q", rec.authHeader)
	}
	if rec.contentType != "application/json" {
		t.Errorf("content-type = %q", rec.contentType)
	}

	var got types.PatchEnvelope
	if err := json.Unmarshal(rec.body, &got); err != nil {
		t.Fatalf("decoding posted body: %v", err)
	}
	if got.Patch.ID != "patch-1" {
		t.Errorf("envelope.Patch.ID = %q", got.Patch.ID)
	}
	if got.Patch.Status != "SUCCESS" {
		t.Errorf("envelope.Patch.Status = %q", got.Patch.Status)
	}

	// Job-side assertions: source ref, packages, sink, source creds.
	if capturedJob.ID != "patch-1" {
		t.Errorf("job.ID = %q", capturedJob.ID)
	}
	if capturedJob.Job.Source.Ref != "alpine:3.18" {
		t.Errorf("job.Source.Ref = %q", capturedJob.Job.Source.Ref)
	}
	if capturedJob.Job.SourceCredentials == nil ||
		capturedJob.Job.SourceCredentials.Username != "src-user" ||
		capturedJob.Job.SourceCredentials.Password != "src-pass" {
		t.Errorf("source creds not threaded from REGISTRY_USER/REGISTRY_PASS: %+v", capturedJob.Job.SourceCredentials)
	}
	if len(capturedJob.Job.Packages) != 1 || capturedJob.Job.Packages[0].Name != "openssl" {
		t.Errorf("packages = %+v", capturedJob.Job.Packages)
	}
	if capturedJob.Job.Sink.Kind != "registry" {
		t.Errorf("sink.kind = %q", capturedJob.Job.Sink.Kind)
	}
	if capturedJob.Job.Sink.Registry == nil ||
		capturedJob.Job.Sink.Registry.Ref != "registry.example.com/app" ||
		capturedJob.Job.Sink.Registry.Tag != "patched" {
		t.Errorf("sink.registry = %+v", capturedJob.Job.Sink.Registry)
	}
	// Sink creds are sourced from SINK_REGISTRY_USER/PASS env (the env
	// fallback inside runPatch). They land on the per-job Registry
	// Credentials field via buildPatchSink and ALSO on
	// Patcher.SensorRegistryCreds — both paths converge to the same
	// values, which is the simpler and safer design (sink.New picks
	// per-job creds first, falls back to SensorRegistryCreds, and
	// either resolves to the right thing).
	if capturedJob.Job.Sink.Registry.Credentials == nil ||
		capturedJob.Job.Sink.Registry.Credentials.Username != "sink-user" ||
		capturedJob.Job.Sink.Registry.Credentials.Password != "sink-pass" {
		t.Errorf("sink creds from SINK_REGISTRY_USER/PASS env not threaded onto per-job sink: %+v",
			capturedJob.Job.Sink.Registry.Credentials)
	}
}

func TestRunPatchSinkCredsViaFlags(t *testing.T) {
	// Confirm --sink-username / --sink-password populate the sink
	// registry's per-job Credentials field directly. Distinct from the
	// env-fallback path, which routes via SensorRegistryCreds.
	srv, _ := newRecorderServer(t)

	var capturedJob types.PatchJob
	withStubPatchExecute(t, func(ctx context.Context, p *patcher.Patcher, job types.PatchJob) (*types.PatchEnvelope, error) {
		capturedJob = job
		return &types.PatchEnvelope{
			Patch: types.EnvelopePatch{ID: job.ID, Status: "SUCCESS"},
			Sink:  types.EnvelopePatchSink{Kind: "registry"},
		}, nil
	})

	withEnv(t, "REGISTRY_USER", "")
	withEnv(t, "REGISTRY_PASS", "")
	withEnv(t, "SINK_REGISTRY_USER", "")
	withEnv(t, "SINK_REGISTRY_PASS", "")

	resetPatchFlags(t)
	rootCmd.SetArgs([]string{
		"patch",
		"alpine:3.18",
		"--patch-id", "patch-creds-flags",
		"--upload-result-url", srv.URL,
		"--api-key", "k",
		"--packages-json", `[{"name":"openssl","targetVersion":"x"}]`,
		"--sink-kind", "registry",
		"--sink-ref", "registry.example.com/app",
		"--sink-tag", "t1",
		"--sink-username", "flag-user",
		"--sink-password", "flag-pass",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if capturedJob.Job.Sink.Registry == nil ||
		capturedJob.Job.Sink.Registry.Credentials == nil ||
		capturedJob.Job.Sink.Registry.Credentials.Username != "flag-user" {
		t.Errorf("sink creds via flags not threaded onto per-job sink: %+v", capturedJob.Job.Sink.Registry)
	}
}

func TestRunPatchFailureSendsFailedEnvelope(t *testing.T) {
	srv, rec := newRecorderServer(t)

	withStubPatchExecute(t, func(ctx context.Context, p *patcher.Patcher, job types.PatchJob) (*types.PatchEnvelope, error) {
		return nil, errors.New("buildah: simulated push failure")
	})

	resetPatchFlags(t)
	rootCmd.SetArgs([]string{
		"patch",
		"alpine:3.18",
		"--patch-id", "patch-fail",
		"--upload-result-url", srv.URL,
		"--api-key", "k",
		"--packages-json", `[{"name":"openssl","targetVersion":"3.0.2"}]`,
		"--sink-kind", "registry",
		"--sink-ref", "registry.example.com/app",
		"--sink-tag", "t1",
	})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if !strings.Contains(err.Error(), "buildah: simulated push failure") {
		t.Errorf("error should wrap underlying cause: %v", err)
	}

	if rec.hits.Load() != 1 {
		t.Fatalf("recorder hits = %d, want 1", rec.hits.Load())
	}
	var got types.PatchEnvelope
	if err := json.Unmarshal(rec.body, &got); err != nil {
		t.Fatalf("decoding posted body: %v", err)
	}
	if got.Patch.Status != "FAILED" {
		t.Errorf("Patch.Status = %q, want FAILED", got.Patch.Status)
	}
	if len(got.Results) != 1 || got.Results[0].Status != "FAILED" {
		t.Errorf("expected one FAILED package result; got %+v", got.Results)
	}
	if got.Results[0].Error == "" || !strings.Contains(got.Results[0].Error, "buildah: simulated push failure") {
		t.Errorf("per-package Error should carry the failure message, got %q", got.Results[0].Error)
	}
	if got.Tooling["error"] == "" {
		t.Errorf("Tooling[error] should carry the failure message")
	}
}

// TestRunPatchFailureEnvelopeMatchesDashboardContract is the
// regression-net for the trio of dashboard-contract bugs we fixed:
//
//   - envelope.patched.sizeBytes must be present (zero, not undefined)
//     so /api/patches/upload's BigInt(...) doesn't throw and 500.
//   - envelope.patched as a JSON object must contain "sizeBytes" — the
//     prior `Patched: EnvelopePatchedImage{}` with omitempty rendered
//     as `"patched":{}`, which broke the BigInt call downstream.
//   - per-package status must be "FAILED" so the dashboard's
//     envelope.results.find(r => r.status === "FAILED") locates the
//     buildah error string instead of falling back to the literal
//     "Patch failed".
//
// Driving this test through a full JSON marshal/unmarshal of what the
// HTTP body would be — not just inspecting the Go struct — is the
// piece that the prior tests missed.
func TestRunPatchFailureEnvelopeMatchesDashboardContract(t *testing.T) {
	srv, rec := newRecorderServer(t)

	withStubPatchExecute(t, func(ctx context.Context, p *patcher.Patcher, job types.PatchJob) (*types.PatchEnvelope, error) {
		return nil, errors.New("buildah: pkg manager unsupported")
	})

	resetPatchFlags(t)
	rootCmd.SetArgs([]string{
		"patch",
		"alpine:3.18",
		"--patch-id", "patch-contract",
		"--upload-result-url", srv.URL,
		"--api-key", "k",
		"--packages-json", `[{"name":"openssl","targetVersion":"3.0.2","packageManager":"apk"}]`,
		"--sink-kind", "registry",
		"--sink-ref", "registry.example.com/app",
		"--sink-tag", "t",
	})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected non-nil error from failing patch")
	}

	if rec.hits.Load() != 1 {
		t.Fatalf("recorder hits = %d", rec.hits.Load())
	}

	// Decode the on-the-wire JSON loosely: the dashboard's TS code does
	// roughly the same — it doesn't share Go struct definitions, just
	// reads named keys. If those keys aren't where the dashboard expects
	// them, the dashboard 500s.
	var asMap map[string]any
	if err := json.Unmarshal(rec.body, &asMap); err != nil {
		t.Fatalf("decoding wire JSON: %v", err)
	}

	// "patched" must be an object with a numeric "sizeBytes" — not {}.
	patched, ok := asMap["patched"].(map[string]any)
	if !ok {
		t.Fatalf("patched is not an object: %v (type %T)", asMap["patched"], asMap["patched"])
	}
	sz, present := patched["sizeBytes"]
	if !present {
		t.Errorf("patched.sizeBytes is absent — dashboard does BigInt(undefined) → throws. Body = %s", string(rec.body))
	}
	// JSON numbers come back as float64 in a generic map decode; assert it.
	if got, ok := sz.(float64); !ok || got != 0 {
		t.Errorf("patched.sizeBytes = %v (type %T); expected numeric 0", sz, sz)
	}

	// per-package result must be "FAILED" with the buildah error
	// stitched through. The dashboard greps results for status==FAILED;
	// SKIPPED would silently lose the error text.
	results, _ := asMap["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("expected 1 result on the wire; got %d", len(results))
	}
	r0 := results[0].(map[string]any)
	if r0["status"] != "FAILED" {
		t.Errorf("results[0].status = %v, want FAILED", r0["status"])
	}
	if e, _ := r0["error"].(string); e == "" || !strings.Contains(e, "pkg manager unsupported") {
		t.Errorf("results[0].error should carry buildah cause, got %q", e)
	}

	// Patch.Status at the envelope level still FAILED (consumed alongside
	// the per-package signal — both have to agree for the dashboard's
	// allSucceeded check to flip the row to FAILED).
	patch, _ := asMap["patch"].(map[string]any)
	if patch["status"] != "FAILED" {
		t.Errorf("patch.status = %v, want FAILED", patch["status"])
	}

	// And finally a strict-typed parse to catch any latent breakage in
	// the Go-side schema (a future dev who reintroduces omitempty on
	// Size would still pass the loose parse above, since the wire JSON
	// would simply omit sizeBytes — but this strict re-marshal/round-trip
	// pins the expected shape).
	var strict types.PatchEnvelope
	if err := json.Unmarshal(rec.body, &strict); err != nil {
		t.Fatalf("strict round-trip decoding: %v", err)
	}
	if strict.Patched.Size != 0 {
		t.Errorf("strict Patched.Size = %d, want 0", strict.Patched.Size)
	}
}

// PARTIAL/SUCCESS pass through; FAILED status from the envelope itself
// (every package install failed inside Execute) becomes a non-zero exit.
// Mirrors agent-mode's processPatchJob handling.
func TestRunPatchFailedEnvelopeStatusReturnsError(t *testing.T) {
	srv, _ := newRecorderServer(t)

	withStubPatchExecute(t, func(ctx context.Context, p *patcher.Patcher, job types.PatchJob) (*types.PatchEnvelope, error) {
		return &types.PatchEnvelope{
			Patch: types.EnvelopePatch{ID: job.ID, Status: "FAILED"},
			Sink:  types.EnvelopePatchSink{Kind: "registry"},
			Results: []types.PatchPackageResult{
				{Package: "openssl", Status: "FAILED", Error: "no candidate"},
			},
		}, nil
	})

	resetPatchFlags(t)
	rootCmd.SetArgs([]string{
		"patch",
		"alpine:3.18",
		"--patch-id", "patch-allfail",
		"--upload-result-url", srv.URL,
		"--api-key", "k",
		"--packages-json", `[{"name":"openssl","targetVersion":"3.0.2"}]`,
		"--sink-kind", "registry",
		"--sink-ref", "registry.example.com/app",
		"--sink-tag", "t",
	})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when envelope.Patch.Status=FAILED")
	}
	if !strings.Contains(err.Error(), "all packages failed") {
		t.Errorf("error should call out the all-failed condition: %v", err)
	}
}

func TestRunPatchMissingFlags(t *testing.T) {
	withStubPatchExecute(t, func(ctx context.Context, p *patcher.Patcher, job types.PatchJob) (*types.PatchEnvelope, error) {
		t.Fatal("Execute should not be called when required flags are missing")
		return nil, nil
	})

	resetPatchFlags(t)
	rootCmd.SetArgs([]string{
		"patch",
		"alpine:3.18",
		"--patch-id", "p1",
		// upload-result-url, api-key, packages-json all missing
	})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing flags")
	}
	if !strings.Contains(err.Error(), "missing required flags") {
		t.Errorf("error: %v", err)
	}
}

func TestRunPatchInvalidPackagesJSON(t *testing.T) {
	withStubPatchExecute(t, func(ctx context.Context, p *patcher.Patcher, job types.PatchJob) (*types.PatchEnvelope, error) {
		t.Fatal("Execute should not be called for malformed --packages-json")
		return nil, nil
	})
	srv, _ := newRecorderServer(t)
	resetPatchFlags(t)
	rootCmd.SetArgs([]string{
		"patch",
		"alpine:3.18",
		"--patch-id", "p1",
		"--upload-result-url", srv.URL,
		"--api-key", "k",
		"--packages-json", "not-json",
		"--sink-kind", "registry",
		"--sink-ref", "registry.example.com/app",
		"--sink-tag", "t",
	})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "parsing --packages-json") {
		t.Errorf("error should mention parsing failure: %v", err)
	}
}

func TestRunPatchEmptyPackagesArray(t *testing.T) {
	withStubPatchExecute(t, func(ctx context.Context, p *patcher.Patcher, job types.PatchJob) (*types.PatchEnvelope, error) {
		t.Fatal("Execute should not be called for empty packages array")
		return nil, nil
	})
	srv, _ := newRecorderServer(t)
	resetPatchFlags(t)
	rootCmd.SetArgs([]string{
		"patch",
		"alpine:3.18",
		"--patch-id", "p1",
		"--upload-result-url", srv.URL,
		"--api-key", "k",
		"--packages-json", "[]",
		"--sink-kind", "registry",
		"--sink-ref", "registry.example.com/app",
		"--sink-tag", "t",
	})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "non-empty") {
		t.Errorf("error: %v", err)
	}
}

func TestBuildPatchSinkRegistryFromFlags(t *testing.T) {
	sink, err := buildPatchSink("", "registry", "registry.example.com/app", "v1.0", "u", "p", true)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if sink.Kind != "registry" {
		t.Errorf("kind = %q", sink.Kind)
	}
	if sink.Registry == nil {
		t.Fatal("registry sink missing Registry field")
	}
	if sink.Registry.Ref != "registry.example.com/app" || sink.Registry.Tag != "v1.0" {
		t.Errorf("ref/tag = %q / %q", sink.Registry.Ref, sink.Registry.Tag)
	}
	if !sink.Registry.Insecure {
		t.Error("expected Insecure=true")
	}
	if sink.Registry.Credentials == nil ||
		sink.Registry.Credentials.Username != "u" ||
		sink.Registry.Credentials.Password != "p" {
		t.Errorf("credentials = %+v", sink.Registry.Credentials)
	}
}

func TestBuildPatchSinkRegistryNormalizesScheme(t *testing.T) {
	// http:// scheme on --sink-ref should strip cleanly and force
	// Insecure=true. Mirrors processPatchJob's normalization.
	sink, err := buildPatchSink("", "registry", "http://registry.example.com/app", "v1", "", "", false)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if sink.Registry.Ref != "registry.example.com/app" {
		t.Errorf("ref = %q (scheme not stripped)", sink.Registry.Ref)
	}
	if !sink.Registry.Insecure {
		t.Error("expected Insecure=true after http:// strip")
	}
}

func TestBuildPatchSinkRegistryRequiresRefAndTag(t *testing.T) {
	if _, err := buildPatchSink("", "registry", "", "v1", "", "", false); err == nil {
		t.Error("expected error for missing ref")
	}
	if _, err := buildPatchSink("", "registry", "registry.example.com/app", "", "", "", false); err == nil {
		t.Error("expected error for missing tag")
	}
}

func TestBuildPatchSinkS3RequiresJSON(t *testing.T) {
	if _, err := buildPatchSink("", "s3", "", "", "", "", false); err == nil {
		t.Error("expected error: s3 sink without --sink-spec-json")
	}
	if _, err := buildPatchSink("", "presigned", "", "", "", "", false); err == nil {
		t.Error("expected error: presigned sink without --sink-spec-json")
	}
}

func TestBuildPatchSinkUnknownKind(t *testing.T) {
	if _, err := buildPatchSink("", "garbage", "x", "y", "", "", false); err == nil {
		t.Error("expected error for unknown kind")
	}
}

func TestBuildPatchSinkSpecJSON(t *testing.T) {
	// Full JSON spec should parse and override the individual flags.
	specJSON := `{"kind":"s3","s3":{"bucket":"b","keyPrefix":"p/"}}`
	sink, err := buildPatchSink(specJSON, "registry", "ignored", "ignored", "", "", false)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if sink.Kind != "s3" {
		t.Errorf("kind = %q (specJSON should override --sink-kind)", sink.Kind)
	}
	if sink.S3 == nil || sink.S3.Bucket != "b" || sink.S3.KeyPrefix != "p/" {
		t.Errorf("s3 config = %+v", sink.S3)
	}
}

func TestBuildPatchSinkSpecJSONMalformed(t *testing.T) {
	if _, err := buildPatchSink("{not json", "registry", "x", "y", "", "", false); err == nil {
		t.Error("expected error for malformed JSON")
	}
}

func TestBuildPatchSinkSpecJSONMissingKind(t *testing.T) {
	if _, err := buildPatchSink(`{"s3":{"bucket":"b"}}`, "registry", "x", "y", "", "", false); err == nil {
		t.Error("expected error for spec JSON without 'kind'")
	}
}

// TestRunPatchS3StorageInitializedFromEnv pins the env-driven S3
// initialization wired into runPatch. It mirrors scan.go's behavior:
// when HG_S3_BUCKET + HG_S3_ACCESS_KEY (or AWS_ACCESS_KEY_ID) +
// HG_S3_SECRET_KEY (or AWS_SECRET_ACCESS_KEY) are all set,
// Patcher.S3Storage must be non-nil so non-registry sinks
// (--sink-spec-json with kind=s3 or kind=presigned) can actually push.
// Previously cmd/patch.go hardcoded S3Storage: nil, so sink.New errored
// for the s3/presigned cases.
func TestRunPatchS3StorageInitializedFromEnv(t *testing.T) {
	srv, _ := newRecorderServer(t)

	// Use HG_S3_* (highest-priority alias in config.LoadConfig). Region
	// gets a default in NewS3Storage if empty, so we don't have to set
	// it. NewS3Storage with these stub creds shouldn't talk to AWS at
	// construction time — it only configures the client.
	withEnv(t, "HG_S3_BUCKET", "b")
	withEnv(t, "HG_S3_ACCESS_KEY", "ak")
	withEnv(t, "HG_S3_SECRET_KEY", "sk")
	withEnv(t, "HG_S3_REGION", "us-east-1")

	var captured *patcher.Patcher
	withStubPatchExecute(t, func(ctx context.Context, p *patcher.Patcher, job types.PatchJob) (*types.PatchEnvelope, error) {
		captured = p
		return &types.PatchEnvelope{
			Patch: types.EnvelopePatch{ID: job.ID, Status: "SUCCESS"},
			Sink:  types.EnvelopePatchSink{Kind: "registry"},
		}, nil
	})

	resetPatchFlags(t)
	rootCmd.SetArgs([]string{
		"patch",
		"alpine:3.18",
		"--patch-id", "patch-s3-env",
		"--upload-result-url", srv.URL,
		"--api-key", "k",
		"--packages-json", `[{"name":"openssl","targetVersion":"3.0.2"}]`,
		"--sink-kind", "registry",
		"--sink-ref", "registry.example.com/app",
		"--sink-tag", "t",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if captured == nil {
		t.Fatal("stub never observed the Patcher")
	}
	if captured.S3Storage == nil {
		t.Error("Patcher.S3Storage = nil; expected non-nil when HG_S3_* env is set (sink.New for kind=s3/presigned would fail)")
	}
}

// TestRunPatchS3StorageNilWithoutEnvForRegistrySink confirms the
// graceful-fallback half of the contract: when no S3 env is set and
// the sink is registry-only, runPatch must NOT fail. Patcher.S3Storage
// stays nil and registry-kind sinks proceed normally (sink.New only
// touches S3Storage when spec.Kind == "s3" or "presigned").
func TestRunPatchS3StorageNilWithoutEnvForRegistrySink(t *testing.T) {
	srv, _ := newRecorderServer(t)

	// Explicitly clear every env alias config.LoadConfig recognizes so
	// the test isn't sensitive to ambient shell state.
	for _, k := range []string{
		"HG_S3_BUCKET", "S3_BUCKET",
		"HG_S3_ACCESS_KEY", "AWS_ACCESS_KEY_ID",
		"HG_S3_SECRET_KEY", "AWS_SECRET_ACCESS_KEY",
		"HG_S3_REGION", "AWS_REGION",
		"HG_S3_ENDPOINT", "S3_ENDPOINT",
	} {
		withEnv(t, k, "")
	}

	var captured *patcher.Patcher
	withStubPatchExecute(t, func(ctx context.Context, p *patcher.Patcher, job types.PatchJob) (*types.PatchEnvelope, error) {
		captured = p
		return &types.PatchEnvelope{
			Patch: types.EnvelopePatch{ID: job.ID, Status: "SUCCESS"},
			Sink:  types.EnvelopePatchSink{Kind: "registry"},
		}, nil
	})

	resetPatchFlags(t)
	rootCmd.SetArgs([]string{
		"patch",
		"alpine:3.18",
		"--patch-id", "patch-no-s3-env",
		"--upload-result-url", srv.URL,
		"--api-key", "k",
		"--packages-json", `[{"name":"openssl","targetVersion":"3.0.2"}]`,
		"--sink-kind", "registry",
		"--sink-ref", "registry.example.com/app",
		"--sink-tag", "t",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("registry-kind patch must not fail when S3 env is absent: %v", err)
	}
	if captured == nil {
		t.Fatal("stub never observed the Patcher")
	}
	if captured.S3Storage != nil {
		t.Errorf("Patcher.S3Storage = %v; expected nil when S3 env is absent", captured.S3Storage)
	}
}

// TestRunPatchS3SinkRequiresS3Env is the loud-fail half. With sink
// kind=s3 (via --sink-spec-json) and no S3 env configured, runPatch
// must fail before invoking Execute — otherwise sink.New errors deep
// inside the patcher and the dashboard sees an opaque buildah failure.
func TestRunPatchS3SinkRequiresS3Env(t *testing.T) {
	srv, _ := newRecorderServer(t)

	for _, k := range []string{
		"HG_S3_BUCKET", "S3_BUCKET",
		"HG_S3_ACCESS_KEY", "AWS_ACCESS_KEY_ID",
		"HG_S3_SECRET_KEY", "AWS_SECRET_ACCESS_KEY",
	} {
		withEnv(t, k, "")
	}

	withStubPatchExecute(t, func(ctx context.Context, p *patcher.Patcher, job types.PatchJob) (*types.PatchEnvelope, error) {
		t.Fatal("Execute must not run when s3 sink requested without S3 env")
		return nil, nil
	})

	resetPatchFlags(t)
	rootCmd.SetArgs([]string{
		"patch",
		"alpine:3.18",
		"--patch-id", "patch-s3-no-env",
		"--upload-result-url", srv.URL,
		"--api-key", "k",
		"--packages-json", `[{"name":"openssl","targetVersion":"3.0.2"}]`,
		"--sink-spec-json", `{"kind":"s3","s3":{"bucket":"b","keyPrefix":"p/"}}`,
	})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when sink kind=s3 but S3 env is absent")
	}
	if !strings.Contains(err.Error(), "S3 configuration") {
		t.Errorf("error should call out missing S3 config; got: %v", err)
	}
}

// Unused atomic import check — make sure we don't accidentally drop the
// shared recorder helper from export_test.
var _ = atomic.Int32{}

// Avoid an unused-context-import lint if the file ever is reduced. The
// stubs above already use it, but a defensive sentinel is cheap.
var _ = context.Background
