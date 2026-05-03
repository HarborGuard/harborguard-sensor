package sink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/HarborGuard/harborguard-sensor/internal/storage"
	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

// s3Uploader is the subset of *storage.S3Storage that the s3 sink needs.
// Defining it here lets the sink test inject a fake without standing up
// a real S3 endpoint or driving the AWS SDK.
type s3Uploader interface {
	UploadArtifactReader(ctx context.Context, key string, body io.Reader, contentLength int64) error
	GetPresignedURL(key string, expiresIn time.Duration) (string, error)
}

// Compile-time check: the production type satisfies the seam.
var _ s3Uploader = (*storage.S3Storage)(nil)

// s3Sink uploads the patched tarball to S3. When presign is true, it also
// returns a time-limited GET URL for downstream consumption.
//
// The sink computes a SHA256 over the tar bytes during the upload pass
// (single-pass, via io.TeeReader) and surfaces it in Result.Digest as
// "sha256:<hex>". For non-registry sinks this is the only meaningful
// integrity signal the dashboard has — registry sinks instead populate
// Digest with the OCI manifest digest reported by skopeo.
type s3Sink struct {
	bucket     string
	keyPrefix  string
	s3         s3Uploader
	presign    bool
	presignTTL time.Duration
}

func newS3Sink(spec types.PatchSinkS3, s3 s3Uploader, presign bool, ttlSecs int) *s3Sink {
	prefix := spec.KeyPrefix
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return &s3Sink{
		bucket:     spec.Bucket,
		keyPrefix:  prefix,
		s3:         s3,
		presign:    presign,
		presignTTL: time.Duration(ttlSecs) * time.Second,
	}
}

func (s *s3Sink) Push(ctx context.Context, tarPath string) (*Result, error) {
	key := path.Join(strings.TrimSuffix(s.keyPrefix, "/"), fmt.Sprintf("patched-%d.tar", time.Now().Unix()))

	f, err := os.Open(tarPath)
	if err != nil {
		return nil, fmt.Errorf("open patched tar: %w", err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat patched tar: %w", err)
	}

	// Hash the tar bytes in the same pass that streams them to S3:
	// io.TeeReader reads from f and writes every byte to the hasher,
	// so PutObject draining the reader populates the hash for free.
	// This is what registry sinks would call the OCI manifest digest;
	// for s3/presigned, the SHA256 of the uploaded tar is the closest
	// equivalent integrity signal.
	hasher := sha256.New()
	body := io.TeeReader(f, hasher)

	uploadCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	if err := s.s3.UploadArtifactReader(uploadCtx, key, body, stat.Size()); err != nil {
		return nil, fmt.Errorf("s3 upload: %w", err)
	}

	digest := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	result := &Result{Location: key, Digest: digest}
	if s.presign {
		url, err := s.s3.GetPresignedURL(key, s.presignTTL)
		if err != nil {
			return nil, fmt.Errorf("presigning: %w", err)
		}
		result.URL = url
	}
	return result, nil
}
