package sink

import (
	"context"
	"fmt"

	"github.com/HarborGuard/harborguard-sensor/internal/storage"
	"github.com/HarborGuard/harborguard-sensor/internal/types"
)

// Sink ships a patched image tarball to an external destination.
// The sensor never retains the tarball after a successful Push.
type Sink interface {
	// Push uploads the patched image from tarPath. Implementations must
	// return a location descriptor and may include a URL or manifest digest.
	Push(ctx context.Context, tarPath string) (*Result, error)
}

// Result describes where the patched image ended up.
type Result struct {
	Location string // registry ref or s3 key
	URL      string // presigned URL if applicable
	Digest   string // manifest digest after push (registry only)
}

// New constructs a Sink from the job spec. sensorRegistryCreds are the
// fallback credentials resolved for the sensor itself (e.g. from the
// registry discoverer); used only for Registry sinks when the job doesn't
// supply its own. sourceRef is the original image reference, used to
// synthesize a destination repo path when the sink's Ref is a bare
// registry host.
func New(spec types.PatchSink, sourceRef string, s3 *storage.S3Storage, sensorRegistryCreds *types.RegistryCredentials) (Sink, error) {
	switch spec.Kind {
	case "registry":
		if spec.Registry == nil {
			return nil, fmt.Errorf("sink.registry required for kind=registry")
		}
		return newRegistrySink(*spec.Registry, sourceRef, sensorRegistryCreds), nil
	case "s3":
		if spec.S3 == nil {
			return nil, fmt.Errorf("sink.s3 required for kind=s3")
		}
		if s3 == nil {
			return nil, fmt.Errorf("S3 sink requested but sensor S3 storage is not configured")
		}
		return newS3Sink(*spec.S3, s3, false, 0), nil
	case "presigned":
		if spec.Presigned == nil {
			return nil, fmt.Errorf("sink.presigned required for kind=presigned")
		}
		if s3 == nil {
			return nil, fmt.Errorf("presigned sink requested but sensor S3 storage is not configured")
		}
		ttl := spec.Presigned.TTLSecs
		if ttl <= 0 {
			ttl = 3600
		}
		return newS3Sink(types.PatchSinkS3{
			Bucket:    spec.Presigned.Bucket,
			KeyPrefix: spec.Presigned.KeyPrefix,
		}, s3, true, ttl), nil
	default:
		return nil, fmt.Errorf("unknown sink kind: %q", spec.Kind)
	}
}
