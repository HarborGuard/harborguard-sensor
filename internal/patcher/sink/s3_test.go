package sink

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

// fakeS3Uploader records what the sink streamed to S3 so we can verify
// (a) the bytes that hit S3 are exactly the tar contents and (b) the
// digest the sink reports matches an externally computed SHA256 over
// the same bytes.
type fakeS3Uploader struct {
	captured     bytes.Buffer
	gotKey       string
	gotLen       int64
	presignURL   string
	presignKey   string
	presignTTL   time.Duration
	uploadErr    error
}

func (f *fakeS3Uploader) UploadArtifactReader(_ context.Context, key string, body io.Reader, contentLength int64) error {
	if f.uploadErr != nil {
		return f.uploadErr
	}
	f.gotKey = key
	f.gotLen = contentLength
	if _, err := io.Copy(&f.captured, body); err != nil {
		return err
	}
	return nil
}

func (f *fakeS3Uploader) GetPresignedURL(key string, expiresIn time.Duration) (string, error) {
	f.presignKey = key
	f.presignTTL = expiresIn
	if f.presignURL == "" {
		return "https://fake.s3/" + key, nil
	}
	return f.presignURL, nil
}

// digestPattern is the wire format the dashboard's patch_operations
// ingest path expects: "sha256:" followed by 64 lowercase hex chars.
// Matches what skopeo emits for registry pushes, so registry vs s3
// sinks produce indistinguishable shapes downstream.
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func writeFixtureTar(t *testing.T, contents []byte) string {
	t.Helper()
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "patched.tar")
	if err := os.WriteFile(tarPath, contents, 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return tarPath
}

func TestS3SinkPushPopulatesSHA256Digest(t *testing.T) {
	// Deterministic, mixed-byte payload so the hash is recomputable
	// and the comparison isn't accidentally hashing an empty buffer.
	payload := bytes.Repeat([]byte("HARBORGUARD-PATCHED-TAR\x00\x01\x02"), 137)
	tarPath := writeFixtureTar(t, payload)

	uploader := &fakeS3Uploader{}
	s := newS3Sink(types.PatchSinkS3{Bucket: "b", KeyPrefix: "patches/p1/"}, uploader, false, 0)

	res, err := s.Push(context.Background(), tarPath)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if res == nil {
		t.Fatal("Push returned nil result")
	}

	// 1. Format: "sha256:<64-hex>" — matches what registry sinks emit.
	if !digestPattern.MatchString(res.Digest) {
		t.Errorf("Result.Digest = %q; want match %s", res.Digest, digestPattern)
	}

	// 2. Correctness: the digest must match an externally computed
	//    SHA256 over the same bytes the uploader received. Hashing the
	//    file contents from disk independently catches any logic bug
	//    where the sink hashed the wrong bytes (e.g. the key, or the
	//    Reader before TeeReader was wired in).
	external := sha256.Sum256(payload)
	wantDigest := "sha256:" + hex.EncodeToString(external[:])
	if res.Digest != wantDigest {
		t.Errorf("Result.Digest = %q; want %q (externally computed over fixture bytes)", res.Digest, wantDigest)
	}

	// 3. The bytes the SDK saw are exactly the tar contents — confirms
	//    TeeReader didn't swallow or reorder data on its way through.
	if !bytes.Equal(uploader.captured.Bytes(), payload) {
		t.Errorf("uploaded body differs from tar contents (got %d bytes, want %d)",
			uploader.captured.Len(), len(payload))
	}
	if uploader.gotLen != int64(len(payload)) {
		t.Errorf("uploader saw contentLength=%d; want %d", uploader.gotLen, len(payload))
	}

	// 4. Location should reflect the keyPrefix the dashboard supplied.
	if res.Location == "" {
		t.Error("Result.Location is empty")
	}
}

func TestS3SinkPushPresignedAlsoEmitsDigest(t *testing.T) {
	// Presigned mode goes through the same upload path, so it should
	// produce the same digest format. Pinning this keeps Test 5 of the
	// cloud-patch e2e green for the presigned variant too.
	payload := []byte("presigned-fixture-bytes-not-empty")
	tarPath := writeFixtureTar(t, payload)

	uploader := &fakeS3Uploader{presignURL: "https://signed.example/object?sig=x"}
	s := newS3Sink(types.PatchSinkS3{Bucket: "b", KeyPrefix: "patches/p2"}, uploader, true, 1800)

	res, err := s.Push(context.Background(), tarPath)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if !digestPattern.MatchString(res.Digest) {
		t.Errorf("presigned: Result.Digest = %q; want match %s", res.Digest, digestPattern)
	}
	external := sha256.Sum256(payload)
	if res.Digest != "sha256:"+hex.EncodeToString(external[:]) {
		t.Errorf("presigned: Result.Digest does not match externally computed hash")
	}
	if res.URL != "https://signed.example/object?sig=x" {
		t.Errorf("presigned: Result.URL = %q; want presigned URL", res.URL)
	}
	if uploader.presignTTL != 1800*time.Second {
		t.Errorf("presigned: TTL = %v; want 30m", uploader.presignTTL)
	}
}

func TestS3SinkPushUploadErrorPropagates(t *testing.T) {
	// A failed upload must surface as an error from Push so the
	// patcher returns early — not silently produce an envelope with
	// a bogus digest of zero bytes.
	tarPath := writeFixtureTar(t, []byte("doesn't matter"))
	uploader := &fakeS3Uploader{uploadErr: io.ErrUnexpectedEOF}
	s := newS3Sink(types.PatchSinkS3{}, uploader, false, 0)

	if _, err := s.Push(context.Background(), tarPath); err == nil {
		t.Fatal("expected upload error, got nil")
	}
}
