package scanner

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// javaArtifactExts lists file suffixes counted as Java-bearing artifacts.
// Match is case-insensitive on the suffix only (no path inspection beyond that).
//
// .jar, .war, .ear   — standard Java archive families
// .par               — OSGi persistence archive (rarer but seen in enterprise apps)
// .jpi, .hpi         — Jenkins plugin formats (jpi is the modern .hpi)
// .sar               — JBoss/WildFly service archive
var javaArtifactExts = []string{".jar", ".war", ".ear", ".par", ".jpi", ".hpi", ".sar"}

// javaTelemetry tallies file counts and a small sample of paths from one
// docker-archive tar walk. Always-on, INFO-level, prefix `[telemetry] java-share`.
// We deliberately keep it tiny: aggregate counts + first 5 sample paths,
// truncated, so the line is grep-friendly across thousands of scans.
type javaTelemetry struct {
	totalFiles         int64
	javaCount          int64
	layerCount         int
	totalImageSize     int64
	javaSamplePaths    []string
	maxSamples         int
	walkErr            string
}

// emitJavaTelemetry walks the docker-archive at tarPath and emits a single
// stable INFO line summarizing Java artifact prevalence. The walk is bounded
// by the existing docker-archive read; we do not pull bytes for non-tar
// entries beyond what's required to find layer member listings. Errors are
// captured into the line as walk_err= but never abort the scan.
//
// Format is JSON for machine aggregation. The prefix `[telemetry] java-share`
// is stable across releases.
func emitJavaTelemetry(scanID, imageRef, tarPath string) {
	t := &javaTelemetry{maxSamples: 5}
	t.walk(tarPath)

	// Total image size = sum of layer compressed sizes if available; fall
	// back to tar file size on disk so we always report something.
	if t.totalImageSize == 0 {
		if fi, err := os.Stat(tarPath); err == nil {
			t.totalImageSize = fi.Size()
		}
	}

	payload := map[string]interface{}{
		"scan_id":               scanID,
		"image_ref":             imageRef,
		"total_files":           t.totalFiles,
		"java_artifact_count":   t.javaCount,
		"java_artifact_paths":   t.javaSamplePaths,
		"layer_count":           t.layerCount,
		"total_image_size_bytes": t.totalImageSize,
	}
	if t.walkErr != "" {
		payload["walk_err"] = t.walkErr
	}
	b, err := json.Marshal(payload)
	if err != nil {
		// Marshaling shouldn't fail on this shape, but keep the
		// invariant that telemetry never breaks scans.
		fmt.Fprintf(os.Stderr, "[telemetry] java-share marshal_err=%q scan_id=%s\n", err.Error(), scanID)
		return
	}
	fmt.Fprintf(os.Stderr, "[telemetry] java-share %s\n", string(b))
}

// walk reads a docker-archive (uncompressed outer tar with layer.tar members
// per the OCI/Docker save format). For each layer member it streams the
// inner tar and counts files, recording the first maxSamples Java artifact
// paths verbatim (truncated per-path to 256 chars to bound log line size).
func (t *javaTelemetry) walk(tarPath string) {
	f, err := os.Open(tarPath)
	if err != nil {
		t.walkErr = "open: " + err.Error()
		return
	}
	defer f.Close()

	outer := tar.NewReader(f)
	for {
		h, err := outer.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.walkErr = "outer-read: " + err.Error()
			return
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			continue
		}
		name := h.Name
		// Layer detection across the formats skopeo emits:
		//   * docker-archive (default): top-level `<sha>.tar` per layer,
		//     plus `<id>/layer.tar` symlinks pointing to them. We match the
		//     top-level files only — the symlinks aren't TypeReg so they
		//     skip naturally.
		//   * docker-archive (legacy/older docker save): `<id>/layer.tar`
		//     as TypeReg with the actual bytes inline.
		//   * oci layout: `blobs/sha256/<digest>` (gzip-compressed layers,
		//     plus a small JSON config blob — the inner-walk gracefully
		//     skips non-tar blobs).
		base := name
		if i := strings.LastIndex(name, "/"); i >= 0 {
			base = name[i+1:]
		}
		isTopLevelLayer := !strings.Contains(name, "/") &&
			strings.HasSuffix(name, ".tar") && len(base) >= 64
		isPerIDLayer := strings.HasSuffix(name, "/layer.tar")
		isOCIBlob := strings.HasPrefix(name, "blobs/sha256/")
		if !isTopLevelLayer && !isPerIDLayer && !isOCIBlob {
			continue
		}
		t.layerCount++
		t.totalImageSize += h.Size
		t.walkLayer(outer, name)
	}
}

// walkLayer streams an inner layer (possibly gzip-compressed) and tallies
// files. Errors inside one layer are recorded but don't abort the outer walk
// — partial telemetry is better than none.
func (t *javaTelemetry) walkLayer(r io.Reader, layerName string) {
	// Peek for gzip magic bytes via a buffered reader. Skopeo's
	// docker-archive output is uncompressed `layer.tar`, but OCI layout
	// blobs from `skopeo copy ... oci:` are typically gzip. Either may
	// appear in `blobs/sha256/<digest>` depending on registry.
	br := newPeekReader(r, 2)
	magic, _ := br.peek(2)
	var inner io.Reader = br
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			// Not actually gzip (e.g. config blob in OCI layout).
			// Skip this entry quietly.
			return
		}
		defer gz.Close()
		inner = gz
	}

	tr := tar.NewReader(inner)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			// Likely a non-tar blob (image config JSON in OCI layout).
			// Decrement layer count to keep the metric honest, then bail.
			t.layerCount--
			return
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			continue
		}
		t.totalFiles++
		if isJavaArtifact(h.Name) {
			t.javaCount++
			if len(t.javaSamplePaths) < t.maxSamples {
				p := h.Name
				if len(p) > 256 {
					p = p[:256]
				}
				t.javaSamplePaths = append(t.javaSamplePaths, p)
			}
		}
	}
}

func isJavaArtifact(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	if ext == "" {
		return false
	}
	for _, e := range javaArtifactExts {
		if ext == e {
			return true
		}
	}
	return false
}

// peekReader wraps an io.Reader with a tiny in-memory peek buffer so we can
// detect gzip magic without consuming the stream. Stdlib bufio.Reader would
// also work; this version stays trivial and avoids allocating a 4 KB default
// buffer per layer.
type peekReader struct {
	r       io.Reader
	buf     []byte
	bufSize int
}

func newPeekReader(r io.Reader, n int) *peekReader {
	return &peekReader{r: r, bufSize: n}
}

func (p *peekReader) peek(n int) ([]byte, error) {
	if len(p.buf) >= n {
		return p.buf[:n], nil
	}
	need := n - len(p.buf)
	tmp := make([]byte, need)
	got, err := io.ReadFull(p.r, tmp)
	p.buf = append(p.buf, tmp[:got]...)
	if err != nil {
		return p.buf, err
	}
	return p.buf[:n], nil
}

func (p *peekReader) Read(b []byte) (int, error) {
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		return n, nil
	}
	return p.r.Read(b)
}
