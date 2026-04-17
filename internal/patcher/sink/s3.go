package sink

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/HarborGuard/harborguard-sensor/internal/storage"
	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

// s3Sink uploads the patched tarball to S3. When presign is true, it also
// returns a time-limited GET URL for downstream consumption.
type s3Sink struct {
	bucket     string
	keyPrefix  string
	s3         *storage.S3Storage
	presign    bool
	presignTTL time.Duration
}

func newS3Sink(spec types.PatchSinkS3, s3 *storage.S3Storage, presign bool, ttlSecs int) *s3Sink {
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
	_ = ctx // UploadArtifact uses an internal timeout; context propagation is future work
	key := path.Join(strings.TrimSuffix(s.keyPrefix, "/"), fmt.Sprintf("patched-%d.tar", time.Now().Unix()))
	if _, err := s.s3.UploadArtifact(key, tarPath); err != nil {
		return nil, fmt.Errorf("s3 upload: %w", err)
	}
	result := &Result{Location: key}
	if s.presign {
		url, err := s.s3.GetPresignedURL(key, s.presignTTL)
		if err != nil {
			return nil, fmt.Errorf("presigning: %w", err)
		}
		result.URL = url
	}
	return result, nil
}
