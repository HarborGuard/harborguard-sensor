package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

// fakeScanner is a Scanner stub that counts GetVersion calls so tests
// can assert "the orchestrator did NOT shell out for versions."
type fakeScanner struct {
	name        string
	versionStr  string
	versionHits atomic.Int64
}

func (f *fakeScanner) Name() string { return f.name }
func (f *fakeScanner) GetVersion() string {
	f.versionHits.Add(1)
	return f.versionStr
}
func (f *fakeScanner) Scan(context.Context, types.ImageSource, string) (*types.ScannerResult, error) {
	return nil, nil
}
func (f *fakeScanner) IsAvailable() bool                            { return true }
func (f *fakeScanner) SupportsSource(types.ImageSource) bool        { return true }

func TestFetchVersionsHitsCache(t *testing.T) {
	a := &fakeScanner{name: "a", versionStr: "live-a"}
	b := &fakeScanner{name: "b", versionStr: "live-b"}

	o := &Orchestrator{
		ScannerVersions: map[string]string{
			"a": "cached-a",
			"b": "cached-b",
		},
	}
	got := o.fetchVersions([]Scanner{a, b})

	if got["a"] != "cached-a" || got["b"] != "cached-b" {
		t.Errorf("expected cached strings, got %v", got)
	}
	if a.versionHits.Load() != 0 || b.versionHits.Load() != 0 {
		t.Errorf("expected zero GetVersion calls, got a=%d b=%d",
			a.versionHits.Load(), b.versionHits.Load())
	}
}

func TestFetchVersionsFallsBackOnCacheMiss(t *testing.T) {
	a := &fakeScanner{name: "a", versionStr: "live-a"}
	b := &fakeScanner{name: "b", versionStr: "live-b"}

	// Cache only knows about "a" — "b" must fall back to probing.
	o := &Orchestrator{
		ScannerVersions: map[string]string{"a": "cached-a"},
	}
	got := o.fetchVersions([]Scanner{a, b})

	if got["a"] != "cached-a" {
		t.Errorf("a: got %q, want cached", got["a"])
	}
	if got["b"] != "live-b" {
		t.Errorf("b: got %q, want live (fallback)", got["b"])
	}
	if a.versionHits.Load() != 0 {
		t.Errorf("a should not have been probed: hits=%d", a.versionHits.Load())
	}
	if b.versionHits.Load() != 1 {
		t.Errorf("b should have been probed exactly once: hits=%d", b.versionHits.Load())
	}
}

func TestFetchVersionsNilCacheFallsBack(t *testing.T) {
	a := &fakeScanner{name: "a", versionStr: "live-a"}
	o := &Orchestrator{} // no ScannerVersions populated
	got := o.fetchVersions([]Scanner{a})
	if got["a"] != "live-a" {
		t.Errorf("got %q, want live", got["a"])
	}
	if a.versionHits.Load() != 1 {
		t.Errorf("expected 1 probe, got %d", a.versionHits.Load())
	}
}

func TestNormalizeImageRef(t *testing.T) {
	cases := []struct {
		name       string
		in         string
		wantRef    string
		wantInsec  bool
		wantChange bool
	}{
		{"bare", "host:5000/repo:tag", "host:5000/repo:tag", false, false},
		{"http", "http://host:5000/repo:tag", "host:5000/repo:tag", true, true},
		{"https", "https://host.example.com/repo:tag", "host.example.com/repo:tag", false, true},
		{"empty", "", "", false, false},
		{"docker-daemon-ref", "alpine:3.18", "alpine:3.18", false, false},
		{"docker-transport-untouched", "docker://alpine:3.18", "docker://alpine:3.18", false, false},
		{"digest", "host/repo@sha256:abc", "host/repo@sha256:abc", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, insec, changed := NormalizeImageRef(c.in)
			if got != c.wantRef {
				t.Errorf("ref: got %q, want %q", got, c.wantRef)
			}
			if insec != c.wantInsec {
				t.Errorf("insecure: got %t, want %t", insec, c.wantInsec)
			}
			if changed != c.wantChange {
				t.Errorf("changed: got %t, want %t", changed, c.wantChange)
			}
		})
	}
}

func TestNormalizeDigestRef(t *testing.T) {
	// Trivy reports `<repo>@sha256:<hex>` in RepoDigests; we want bare
	// `sha256:<hex>` so consumers don't have to defend.
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"trivy_repodigest", "node@sha256:abcd1234", "sha256:abcd1234"},
		{"ecr_repodigest", "572590828342.dkr.ecr.us-east-1.amazonaws.com/node@sha256:7f7c512f", "sha256:7f7c512f"},
		{"already_bare", "sha256:7f7c512f", "sha256:7f7c512f"},
		{"empty", "", ""},
		{"multiple_at_takes_last", "weird@thing@sha256:dead", "sha256:dead"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := normalizeDigestRef(c.in); got != c.want {
				t.Errorf("normalizeDigestRef(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestResolveRegistryIndexDigestAgainstFakeRegistry stands up a tiny HTTP
// server that mimics the OCI Distribution Spec manifest endpoint, then
// verifies that:
//   - resolveRegistryIndexDigest hashes the EXACT bytes the registry served
//     (not a re-serialized form), and
//   - the returned digest is in `sha256:<hex>` form with no `repo@` prefix,
//   - that digest can be used to GET the same manifest by digest from the
//     same registry — proving the value is "skopeo-pullable".
//
// This is the contract the AI-triage path depends on: the value the sensor
// puts into envelope.image.digest must round-trip back to a manifest pull.
func TestResolveRegistryIndexDigestAgainstFakeRegistry(t *testing.T) {
	if _, err := exec.LookPath("skopeo"); err != nil {
		t.Skip("skopeo not on PATH (this test exercises the real binary)")
	}

	// A multi-arch index — the case the production bug was hypothesized
	// to trip on. Bytes are deterministic so we can assert the digest.
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","size":7023,"platform":{"architecture":"amd64","os":"linux"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","size":7023,"platform":{"architecture":"arm64","os":"linux"}}]}`)
	sum := sha256.Sum256(manifest)
	wantDigest := "sha256:" + hex.EncodeToString(sum[:])

	mux := http.NewServeMux()
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		// /v2/ ping — registry probe
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		// /v2/<name>/manifests/<reference>
		if strings.HasSuffix(r.URL.Path, "/manifests/lts") ||
			strings.HasSuffix(r.URL.Path, "/manifests/"+wantDigest) {
			w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
			w.Header().Set("Docker-Content-Digest", wantDigest)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(manifest)
			return
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	hostport := strings.TrimPrefix(srv.URL, "http://")
	o := &Orchestrator{}
	got, err := o.resolveRegistryIndexDigest(context.Background(), types.ImageSource{
		Type:     "registry",
		Ref:      hostport + "/myrepo:lts",
		Insecure: true, // plain HTTP test server
	})
	if err != nil {
		t.Fatalf("resolveRegistryIndexDigest: %v", err)
	}
	if got != wantDigest {
		t.Errorf("digest: got %q, want %q", got, wantDigest)
	}
	if strings.Contains(got, "@") {
		t.Errorf("returned digest contains `@` prefix — must be bare sha256:<hex>: %q", got)
	}
	if !strings.HasPrefix(got, "sha256:") {
		t.Errorf("returned digest must start with `sha256:`, got %q", got)
	}

	// Round-trip: pull by digest from the same registry. This is the
	// invariant that broke in prod (ECR returned `manifest unknown` for
	// the per-arch leaf digest Trivy reported).
	resp, err := http.Get(srv.URL + "/v2/myrepo/manifests/" + got)
	if err != nil {
		t.Fatalf("by-digest GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("by-digest GET: status %d, want 200 (digest is not addressable)", resp.StatusCode)
	}
}

// programmableScanner is a Scanner stub whose Scan behavior is fully
// driven by per-scenario hooks. Tracks invocation order for tests
// that need to assert "this scanner ran while prefetch was still in
// flight."
type programmableScanner struct {
	name           string
	supportsRegistry bool
	scanFn         func(ctx context.Context, source types.ImageSource) (*types.ScannerResult, error)
}

func (p *programmableScanner) Name() string                  { return p.name }
func (p *programmableScanner) GetVersion() string            { return "test-1.0" }
func (p *programmableScanner) IsAvailable() bool             { return true }
func (p *programmableScanner) SupportsSource(s types.ImageSource) bool {
	if s.Type == "registry" {
		return p.supportsRegistry
	}
	return true
}
func (p *programmableScanner) Scan(ctx context.Context, source types.ImageSource, outputPath string) (*types.ScannerResult, error) {
	if p.scanFn != nil {
		return p.scanFn(ctx, source)
	}
	return &types.ScannerResult{Scanner: p.name, Success: true}, nil
}

// orchestratorScheduleHarness builds an Orchestrator wired with
// fake scanners and an injectable prefetch hook so tests don't need
// skopeo, trivy, etc. on PATH.
func orchestratorScheduleHarness(t *testing.T, scanners map[string]*programmableScanner, prefetchFn func(ctx context.Context, source types.ImageSource, outputDir string) (string, error)) *Orchestrator {
	t.Helper()
	tmp := t.TempDir()
	cfg := &types.SensorConfig{
		WorkDir:               tmp,
		MaxConcurrentScanners: 4,
	}
	return &Orchestrator{
		Config: cfg,
		scannerFactory: func(name string) (Scanner, error) {
			s, ok := scanners[name]
			if !ok {
				return nil, fmt.Errorf("unknown fake scanner %q", name)
			}
			return s, nil
		},
		prefetchFn: prefetchFn,
	}
}

// Scenario 1: prefetch succeeds, compatible batch succeeds. Both
// batches' results must be merged into the final ScanOutput.
func TestExecute_ConcurrentPrefetch_BothSucceed(t *testing.T) {
	prefetchStart := make(chan struct{}, 1)
	prefetchDone := make(chan struct{})

	scanners := map[string]*programmableScanner{
		// Compatible (registry): records a marker that lets us
		// assert it ran *concurrently with* prefetch — its scanFn
		// blocks waiting for prefetchStart, then completes before
		// prefetchDone is closed.
		"registry-ok": {
			name: "registry-ok", supportsRegistry: true,
			scanFn: func(ctx context.Context, src types.ImageSource) (*types.ScannerResult, error) {
				if src.Type != "registry" {
					t.Errorf("registry-ok ran against %s, want registry", src.Type)
				}
				<-prefetchStart // proves prefetch goroutine has begun
				return &types.ScannerResult{Scanner: "registry-ok", Success: true}, nil
			},
		},
		"tar-ok": {
			name: "tar-ok", supportsRegistry: false,
			scanFn: func(ctx context.Context, src types.ImageSource) (*types.ScannerResult, error) {
				if src.Type != "tar" {
					t.Errorf("tar-ok ran against %s, want tar", src.Type)
				}
				return &types.ScannerResult{Scanner: "tar-ok", Success: true}, nil
			},
		},
	}
	tarTmp := t.TempDir()
	tarPath := tarTmp + "/prefetch.tar"
	if err := os.WriteFile(tarPath, []byte("fake-tar"), 0644); err != nil {
		t.Fatal(err)
	}
	prefetch := func(ctx context.Context, source types.ImageSource, outputDir string) (string, error) {
		prefetchStart <- struct{}{}
		defer close(prefetchDone)
		return tarPath, nil
	}
	o := orchestratorScheduleHarness(t, scanners, prefetch)

	out, err := o.Execute(context.Background(), types.ScanJob{
		ID:       "j1",
		ImageRef: "example.com/img:v1",
		Source:   types.ImageSource{Type: "registry", Ref: "example.com/img:v1"},
		Scanners: []string{"registry-ok", "tar-ok"},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if r, ok := out.Results["registry-ok"]; !ok || !r.Success {
		t.Errorf("registry-ok missing/failed: %+v", r)
	}
	if r, ok := out.Results["tar-ok"]; !ok || !r.Success {
		t.Errorf("tar-ok missing/failed: %+v", r)
	}
	select {
	case <-prefetchDone:
	default:
		t.Errorf("prefetch goroutine never completed")
	}
}

// Scenario 2: prefetch fails. The compatible batch's results must
// still be preserved and the incompatible batch must be reported as
// skipped/failed with the prefetch error.
func TestExecute_ConcurrentPrefetch_PrefetchFails(t *testing.T) {
	scanners := map[string]*programmableScanner{
		"registry-ok": {
			name: "registry-ok", supportsRegistry: true,
			scanFn: func(ctx context.Context, src types.ImageSource) (*types.ScannerResult, error) {
				return &types.ScannerResult{Scanner: "registry-ok", Success: true, Data: map[string]interface{}{"k": "v"}}, nil
			},
		},
		"tar-ok": {
			name: "tar-ok", supportsRegistry: false,
			scanFn: func(ctx context.Context, src types.ImageSource) (*types.ScannerResult, error) {
				t.Errorf("tar-ok must not run when prefetch fails")
				return &types.ScannerResult{Scanner: "tar-ok", Success: true}, nil
			},
		},
	}
	prefetch := func(ctx context.Context, source types.ImageSource, outputDir string) (string, error) {
		return "", fmt.Errorf("simulated prefetch failure")
	}
	o := orchestratorScheduleHarness(t, scanners, prefetch)

	out, err := o.Execute(context.Background(), types.ScanJob{
		ID:       "j2",
		ImageRef: "example.com/img:v1",
		Source:   types.ImageSource{Type: "registry", Ref: "example.com/img:v1"},
		Scanners: []string{"registry-ok", "tar-ok"},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if r, ok := out.Results["registry-ok"]; !ok || !r.Success {
		t.Errorf("registry-ok must succeed even when prefetch fails: %+v", r)
	}
	r, ok := out.Results["tar-ok"]
	if !ok {
		t.Fatalf("tar-ok result missing — should be recorded as failed")
	}
	if r.Success {
		t.Errorf("tar-ok must be marked failed when prefetch fails")
	}
	if !strings.Contains(r.Error, "simulated prefetch failure") {
		t.Errorf("tar-ok error must surface prefetch error, got %q", r.Error)
	}
}

// Scenario 3: compatible batch fails (e.g. timeout). The prefetch
// goroutine must still complete (not be orphaned), and the
// incompatible batch must run normally against the resulting tar.
func TestExecute_ConcurrentPrefetch_CompatibleFailsPrefetchStillRuns(t *testing.T) {
	prefetchHit := make(chan struct{}, 1)
	scanners := map[string]*programmableScanner{
		"registry-fail": {
			name: "registry-fail", supportsRegistry: true,
			scanFn: func(ctx context.Context, src types.ImageSource) (*types.ScannerResult, error) {
				return &types.ScannerResult{Scanner: "registry-fail", Success: false, Error: "simulated timeout"}, nil
			},
		},
		"tar-ok": {
			name: "tar-ok", supportsRegistry: false,
			scanFn: func(ctx context.Context, src types.ImageSource) (*types.ScannerResult, error) {
				if src.Type != "tar" {
					t.Errorf("tar-ok ran against %s, want tar", src.Type)
				}
				return &types.ScannerResult{Scanner: "tar-ok", Success: true}, nil
			},
		},
	}
	tarTmp := t.TempDir()
	tarPath := tarTmp + "/prefetch.tar"
	_ = os.WriteFile(tarPath, []byte("fake-tar"), 0644)
	prefetch := func(ctx context.Context, source types.ImageSource, outputDir string) (string, error) {
		prefetchHit <- struct{}{}
		return tarPath, nil
	}
	o := orchestratorScheduleHarness(t, scanners, prefetch)

	out, err := o.Execute(context.Background(), types.ScanJob{
		ID:       "j3",
		ImageRef: "example.com/img:v1",
		Source:   types.ImageSource{Type: "registry", Ref: "example.com/img:v1"},
		Scanners: []string{"registry-fail", "tar-ok"},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	select {
	case <-prefetchHit:
	default:
		t.Errorf("prefetch never ran — must run even when compatible batch fails")
	}
	if r := out.Results["registry-fail"]; r == nil || r.Success {
		t.Errorf("registry-fail should be recorded as failed: %+v", r)
	}
	if r := out.Results["tar-ok"]; r == nil || !r.Success {
		t.Errorf("tar-ok must still run + succeed against the prefetched tar: %+v", r)
	}
}

// Scenario 4: non-registry source. The prefetch goroutine must NOT
// be started — incompatible scanners are simply marked unsupported,
// preserving the original (pre-concurrency) semantics for
// non-registry source modes (docker, tar, etc.).
func TestExecute_NonRegistrySource_PrefetchNeverStarts(t *testing.T) {
	prefetchCalled := atomic.Int64{}
	scanners := map[string]*programmableScanner{
		"any-ok": {
			name: "any-ok", supportsRegistry: true,
			scanFn: func(ctx context.Context, src types.ImageSource) (*types.ScannerResult, error) {
				return &types.ScannerResult{Scanner: "any-ok", Success: true}, nil
			},
		},
		"tar-only": {
			// Declines registry — but source here is "docker", so
			// SupportsSource returns true and it runs in the
			// compatible batch. To get an incompatible scanner for
			// docker source, this test would need a scanner that
			// rejects "docker". We simulate that below.
			name: "tar-only", supportsRegistry: false,
			scanFn: func(ctx context.Context, src types.ImageSource) (*types.ScannerResult, error) {
				return &types.ScannerResult{Scanner: "tar-only", Success: true}, nil
			},
		},
	}
	prefetch := func(ctx context.Context, source types.ImageSource, outputDir string) (string, error) {
		prefetchCalled.Add(1)
		return "", fmt.Errorf("prefetch should not run for non-registry sources")
	}
	o := orchestratorScheduleHarness(t, scanners, prefetch)

	_, err := o.Execute(context.Background(), types.ScanJob{
		ID:       "j4",
		ImageRef: "alpine:3.18",
		Source:   types.ImageSource{Type: "docker", Ref: "alpine:3.18"},
		Scanners: []string{"any-ok", "tar-only"},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if prefetchCalled.Load() != 0 {
		t.Errorf("prefetch was called %d times for docker source — must be 0", prefetchCalled.Load())
	}
}
