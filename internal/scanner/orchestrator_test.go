package scanner

import (
	"context"
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
