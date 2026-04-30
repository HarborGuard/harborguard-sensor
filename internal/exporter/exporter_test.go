package exporter

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

func TestSplitNameTag(t *testing.T) {
	cases := []struct {
		in        string
		wantName  string
		wantTag   string
	}{
		{"alpine:3.18", "alpine", "3.18"},
		{"docker.io/library/nginx:1.25", "docker.io/library/nginx", "1.25"},
		{"ghcr.io/org/app", "ghcr.io/org/app", ""},
		{"host:5000/repo:tag", "host:5000/repo", "tag"},
		{"alpine:3.18@sha256:abc", "alpine", "3.18"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			name, tag := splitNameTag(c.in)
			if name != c.wantName || tag != c.wantTag {
				t.Errorf("splitNameTag(%q) = (%q, %q); want (%q, %q)",
					c.in, name, tag, c.wantName, c.wantTag)
			}
		})
	}
}

func TestValidateJob(t *testing.T) {
	complete := types.ExportJob{
		ID: "j1",
		Job: types.AgentJobExport{
			Source: types.ImageSource{Ref: "alpine:3.18"},
			Sink: types.ExportSink{
				UploadURL:   "https://example.com/put",
				ExpectedKey: "exports/j1/image.tar",
			},
		},
	}
	t.Run("ok", func(t *testing.T) {
		if err := validateJob(complete); err != nil {
			t.Fatalf("unexpected: %v", err)
		}
	})

	missing := []struct {
		name string
		mut  func(*types.ExportJob)
	}{
		{"missing id", func(j *types.ExportJob) { j.ID = "" }},
		{"missing source ref", func(j *types.ExportJob) { j.Job.Source.Ref = "" }},
		{"missing uploadUrl", func(j *types.ExportJob) { j.Job.Sink.UploadURL = "" }},
		{"missing expectedKey", func(j *types.ExportJob) { j.Job.Sink.ExpectedKey = "" }},
	}
	for _, m := range missing {
		t.Run(m.name, func(t *testing.T) {
			j := complete
			m.mut(&j)
			if err := validateJob(j); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestScrubCreds(t *testing.T) {
	t.Run("redacts password when present", func(t *testing.T) {
		err := fmt.Errorf("auth failed: bad creds (user=alice pass=hunter2)")
		got := scrubCreds(err, &types.RegistryCredentials{Username: "alice", Password: "hunter2"})
		if got == nil || got.Error() == err.Error() {
			t.Fatalf("expected redaction; got %q", got)
		}
		if !strings.Contains(got.Error(), "***REDACTED***") {
			t.Errorf("expected REDACTED marker, got %q", got)
		}
		if strings.Contains(got.Error(), "hunter2") {
			t.Errorf("password not redacted: %q", got)
		}
	})
	t.Run("passthrough when password not in message", func(t *testing.T) {
		err := fmt.Errorf("network unreachable")
		got := scrubCreds(err, &types.RegistryCredentials{Password: "hunter2"})
		if got != err {
			t.Errorf("expected identity passthrough, got %q", got)
		}
	})
	t.Run("nil creds passthrough", func(t *testing.T) {
		err := fmt.Errorf("oops")
		if got := scrubCreds(err, nil); got != err {
			t.Errorf("expected identity passthrough, got %q", got)
		}
	})
	t.Run("nil err returns nil", func(t *testing.T) {
		if got := scrubCreds(nil, &types.RegistryCredentials{Password: "x"}); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})
}

func TestGzipFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "in.bin")
	payload := []byte("the quick brown fox jumps over the lazy dog\n")
	if err := os.WriteFile(src, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "in.bin.gz")
	if err := gzipFile(src, dst); err != nil {
		t.Fatalf("gzipFile: %v", err)
	}
	f, err := os.Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	got, err := io.ReadAll(gz)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("decoded payload = %q, want %q", got, payload)
	}
}

// uploadFile contract (single PUT path): hashes pre-pass, PUTs file
// body, returns size + sha; non-2xx surfaces status + body.
func TestUploadFileSinglePut(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "payload.bin")
	payload := make([]byte, 5*1024*1024)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	if err := os.WriteFile(src, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	wantHasher := sha256.Sum256(payload)
	wantSha := hex.EncodeToString(wantHasher[:])

	var (
		mu        sync.Mutex
		gotMethod string
		gotBody   []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotMethod = r.Method
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		gotBody = body
		w.Header().Set("ETag", `"singleput-etag"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := types.ExportSink{
		UploadURL:   srv.URL,
		ExpectedKey: "k",
	}
	size, sha, err := uploadFile(context.Background(), "apikey", "j1", sink, src)
	if err != nil {
		t.Fatalf("uploadFile: %v", err)
	}
	if size != int64(len(payload)) {
		t.Errorf("size = %d, want %d", size, len(payload))
	}
	if sha != wantSha {
		t.Errorf("sha = %q, want %q", sha, wantSha)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %q", gotMethod)
	}
	if len(gotBody) != len(payload) {
		t.Fatalf("body length = %d, want %d", len(gotBody), len(payload))
	}
	wireHash := sha256.Sum256(gotBody)
	if hex.EncodeToString(wireHash[:]) != wantSha {
		t.Errorf("on-the-wire hash != reported hash")
	}
}

func TestUploadFileSurfacesNon2xx(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("SignatureDoesNotMatch"))
	}))
	defer srv.Close()

	sink := types.ExportSink{UploadURL: srv.URL, ExpectedKey: "k"}
	_, _, err := uploadFile(context.Background(), "", "j1", sink, src)
	if err == nil {
		t.Fatal("expected error on 403")
	}
	if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "SignatureDoesNotMatch") {
		t.Errorf("error should surface status + body, got %q", err.Error())
	}
}

// fakeS3 stores PUT-uploaded parts keyed by part number, returning a
// deterministic ETag (the SHA256 hex prefix) so the test can verify
// what the dashboard's complete handler receives.
type fakeS3 struct {
	mu    sync.Mutex
	parts map[int][]byte
	etag  map[int]string
}

func newFakeS3() *fakeS3 {
	return &fakeS3{parts: map[int][]byte{}, etag: map[int]string{}}
}

// fakeDashboard stitches together init/complete/abort + the per-part
// PUT handlers backed by fakeS3.
type fakeDashboard struct {
	t           *testing.T
	s3          *fakeS3
	srv         *httptest.Server
	partSize    int64
	uploadID    string
	completed   atomic.Bool
	completeReq multipartCompleteRequest
	aborted     atomic.Bool
	failPart    int  // 1-based; PUT to this part returns 500
	failComplete bool
}

func (d *fakeDashboard) URLFor(path string) string { return d.srv.URL + path }

func newFakeDashboard(t *testing.T, partSize int64) *fakeDashboard {
	d := &fakeDashboard{t: t, s3: newFakeS3(), partSize: partSize, uploadID: "upl_test"}
	mux := http.NewServeMux()

	mux.HandleFunc("/multipart/init", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			SizeBytes int64 `json:"sizeBytes"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		numParts := int((req.SizeBytes + d.partSize - 1) / d.partSize)
		urls := make([]string, numParts)
		for i := 0; i < numParts; i++ {
			urls[i] = d.URLFor("/s3/part/" + strconv.Itoa(i+1))
		}
		_ = json.NewEncoder(w).Encode(multipartInitResponse{
			UploadId: d.uploadID,
			PartSize: d.partSize,
			PartUrls: urls,
		})
	})

	mux.HandleFunc("/multipart/complete", func(w http.ResponseWriter, r *http.Request) {
		if d.failComplete {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("complete failed"))
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&d.completeReq)
		d.completed.Store(true)
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/multipart/abort", func(w http.ResponseWriter, r *http.Request) {
		d.aborted.Store(true)
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/s3/part/", func(w http.ResponseWriter, r *http.Request) {
		partStr := strings.TrimPrefix(r.URL.Path, "/s3/part/")
		partNum, err := strconv.Atoi(partStr)
		if err != nil {
			http.Error(w, "bad part", 400)
			return
		}
		if d.failPart != 0 && partNum == d.failPart {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("simulated part failure"))
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		hash := sha256.Sum256(body)
		etag := hex.EncodeToString(hash[:8])
		d.s3.mu.Lock()
		d.s3.parts[partNum] = body
		d.s3.etag[partNum] = etag
		d.s3.mu.Unlock()
		w.Header().Set("ETag", `"`+etag+`"`)
		w.WriteHeader(http.StatusOK)
	})

	d.srv = httptest.NewServer(mux)
	return d
}

func (d *fakeDashboard) sink() types.ExportSink {
	return types.ExportSink{
		UploadURL:               d.URLFor("/s3/single-put"), // unused but type wants non-empty for validation
		ExpectedKey:             "k",
		MultipartThresholdBytes: d.partSize, // anything > partSize will go multipart
		MultipartInitUrl:        d.URLFor("/multipart/init"),
		MultipartCompleteUrl:    d.URLFor("/multipart/complete"),
		MultipartAbortUrl:       d.URLFor("/multipart/abort"),
	}
}

func writePayload(t *testing.T, size int) (string, []byte) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "payload.bin")
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, payload
}

func TestMultipartHappyPath(t *testing.T) {
	const partSize = 1024 * 1024 // 1 MiB
	const fileSize = partSize*3 + 17 // 3 full parts + a tiny tail
	d := newFakeDashboard(t, partSize)
	defer d.srv.Close()

	src, payload := writePayload(t, fileSize)
	wantHasher := sha256.Sum256(payload)
	wantSha := hex.EncodeToString(wantHasher[:])

	size, sha, err := uploadFile(context.Background(), "k", "j1", d.sink(), src)
	if err != nil {
		t.Fatalf("uploadFile: %v", err)
	}
	if size != int64(fileSize) || sha != wantSha {
		t.Errorf("size/sha mismatch: got (%d, %s)", size, sha)
	}
	if !d.completed.Load() {
		t.Fatal("expected complete to fire")
	}
	if d.aborted.Load() {
		t.Fatal("did not expect abort on happy path")
	}

	// Reconstruct the body from stored parts and compare to source.
	d.s3.mu.Lock()
	defer d.s3.mu.Unlock()
	if len(d.s3.parts) != 4 {
		t.Fatalf("got %d parts, want 4", len(d.s3.parts))
	}
	var assembled []byte
	for i := 1; i <= 4; i++ {
		assembled = append(assembled, d.s3.parts[i]...)
	}
	if len(assembled) != fileSize {
		t.Fatalf("reassembled length = %d, want %d", len(assembled), fileSize)
	}
	wireHash := sha256.Sum256(assembled)
	if hex.EncodeToString(wireHash[:]) != wantSha {
		t.Errorf("reassembled hash != source hash")
	}

	// Verify ETags reported to complete match what fake-S3 returned.
	if len(d.completeReq.Parts) != 4 {
		t.Fatalf("complete saw %d parts, want 4", len(d.completeReq.Parts))
	}
	for _, p := range d.completeReq.Parts {
		if p.ETag != d.s3.etag[p.PartNumber] {
			t.Errorf("part %d ETag mismatch: complete=%q s3=%q",
				p.PartNumber, p.ETag, d.s3.etag[p.PartNumber])
		}
	}
	if d.completeReq.UploadId != d.uploadID {
		t.Errorf("complete uploadId = %q, want %q", d.completeReq.UploadId, d.uploadID)
	}
}

func TestMultipartAbortsOnPartFailure(t *testing.T) {
	const partSize = 1024 * 1024
	const fileSize = partSize * 4
	d := newFakeDashboard(t, partSize)
	defer d.srv.Close()
	d.failPart = 2

	src, _ := writePayload(t, fileSize)

	_, _, err := uploadFile(context.Background(), "k", "j1", d.sink(), src)
	if err == nil {
		t.Fatal("expected error from failing part")
	}
	if !strings.Contains(err.Error(), "part 2") {
		t.Errorf("error should mention failing part: %q", err.Error())
	}
	if d.completed.Load() {
		t.Error("complete should not have fired")
	}
	if !d.aborted.Load() {
		t.Error("abort should have fired after part failure")
	}
}

func TestMultipartAbortsOnCompleteFailure(t *testing.T) {
	const partSize = 1024 * 1024
	const fileSize = partSize * 2
	d := newFakeDashboard(t, partSize)
	defer d.srv.Close()
	d.failComplete = true

	src, _ := writePayload(t, fileSize)

	_, _, err := uploadFile(context.Background(), "k", "j1", d.sink(), src)
	if err == nil {
		t.Fatal("expected error from failing complete")
	}
	if !strings.Contains(err.Error(), "complete") {
		t.Errorf("error should mention complete: %q", err.Error())
	}
	if !d.aborted.Load() {
		t.Error("abort should have fired after complete failure")
	}
}

// When size <= threshold we should go single-PUT even if multipart
// URLs are present. Confirms the chooser uses size, not URL presence.
func TestUploadFileChoosesSinglePutBelowThreshold(t *testing.T) {
	const partSize = 10 * 1024 * 1024
	const fileSize = 1024 // way under threshold
	d := newFakeDashboard(t, partSize)
	defer d.srv.Close()

	var singleHit atomic.Bool
	singleSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		singleHit.Store(true)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer singleSrv.Close()

	src, _ := writePayload(t, fileSize)
	sink := d.sink()
	sink.UploadURL = singleSrv.URL
	sink.MultipartThresholdBytes = partSize // file is < this

	if _, _, err := uploadFile(context.Background(), "k", "j1", sink, src); err != nil {
		t.Fatalf("uploadFile: %v", err)
	}
	if !singleHit.Load() {
		t.Error("expected single-PUT path")
	}
	if d.completed.Load() {
		t.Error("multipart complete should not have fired")
	}
}
