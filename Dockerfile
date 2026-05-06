FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder
ARG TARGETOS TARGETARCH
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-s -w" -o /harborguard-sensor .

FROM alpine:3.20
WORKDIR /app

ARG TARGETARCH
ARG TRIVY_VERSION=v0.69.3
ARG DOCKLE_VERSION=0.4.15
ARG OSV_SCANNER_VERSION=v2.2.2
ARG DIVE_VERSION=0.13.1

# Scanner binaries + skopeo for registry image prefetch.
# buildah + fuse-overlayfs enable optional image patching. Whether patching
# is actually usable at runtime is decided by capability probe (buildah on
# PATH; storage driver auto-selects overlay when /dev/fuse is present, else vfs).
RUN apk add --no-cache curl bash ca-certificates skopeo buildah netavark fuse-overlayfs tini \
  && set -eux \
  && echo "Building for architecture: ${TARGETARCH:-not set}" \
  && TARGETARCH="${TARGETARCH:-amd64}" \
  # Create a fake uname that returns the correct architecture for the target platform
  && echo '#!/bin/sh' > /usr/local/bin/uname \
  && echo 'if [ "$1" = "-m" ]; then' >> /usr/local/bin/uname \
  && echo '  case "${TARGETARCH}" in' >> /usr/local/bin/uname \
  && echo '    arm64) echo "aarch64" ;;' >> /usr/local/bin/uname \
  && echo '    amd64) echo "x86_64" ;;' >> /usr/local/bin/uname \
  && echo '    *) echo "x86_64" ;;' >> /usr/local/bin/uname \
  && echo '  esac' >> /usr/local/bin/uname \
  && echo 'else' >> /usr/local/bin/uname \
  && echo '  /bin/uname "$@"' >> /usr/local/bin/uname \
  && echo 'fi' >> /usr/local/bin/uname \
  && chmod +x /usr/local/bin/uname \
  # Install Trivy
  && curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin "${TRIVY_VERSION}" \
  # Install Grype (will use our fake uname)
  && curl -fsSL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin \
  # Install Syft (will use our fake uname)
  && curl -sSfL https://get.anchore.io/syft | sh -s -- -b /usr/local/bin \
  # Remove the fake uname after installation
  && rm /usr/local/bin/uname \
  # Install Dockle (conditional arch)
  && if [ "$TARGETARCH" = "amd64" ]; then \
        DOCKLE_ARCH=64bit; \
     elif [ "$TARGETARCH" = "arm64" ]; then \
        DOCKLE_ARCH=ARM64; \
     else \
        echo "Unsupported architecture: $TARGETARCH" && exit 1; \
     fi \
  && echo "Downloading dockle for ${DOCKLE_ARCH}" \
  && curl -L "https://github.com/goodwithtech/dockle/releases/download/v${DOCKLE_VERSION}/dockle_${DOCKLE_VERSION}_Linux-${DOCKLE_ARCH}.tar.gz" \
       -o /tmp/dockle.tgz \
  && tar -xzf /tmp/dockle.tgz -C /usr/local/bin dockle \
  && rm /tmp/dockle.tgz \
  && chmod +x /usr/local/bin/dockle \
  # Install Dive (dynamic arch)
  && curl -L "https://github.com/wagoodman/dive/releases/download/v${DIVE_VERSION}/dive_${DIVE_VERSION}_linux_${TARGETARCH}.tar.gz" \
       -o /tmp/dive.tgz \
  && tar -xzf /tmp/dive.tgz -C /usr/local/bin dive \
  && rm /tmp/dive.tgz \
  && chmod +x /usr/local/bin/dive \
  # Install OSV Scanner (dynamic arch)
  && curl -L "https://github.com/google/osv-scanner/releases/download/${OSV_SCANNER_VERSION}/osv-scanner_linux_${TARGETARCH}" \
       -o /usr/local/bin/osv-scanner \
  && chmod +x /usr/local/bin/osv-scanner \
  && rm -rf /tmp/* /var/tmp/*

# Workspace (writable runtime caches; populated by sensor-init.sh from the
# baked /opt/sensor/db layer at container start).
RUN mkdir -p /workspace/cache/trivy/db /workspace/cache/grype /workspace/cache/syft /workspace/reports

ENV TRIVY_CACHE_DIR=/workspace/cache/trivy
ENV GRYPE_DB_CACHE_DIR=/workspace/cache/grype
ENV SYFT_CACHE_DIR=/workspace/cache/syft

# Pre-bake scanner databases so ephemeral scan machines start without
# cold-start DB downloads (~3 minutes saved per cold scan).
#
# Each scanner gets its own RUN to keep layers cache-friendly: a Trivy DB
# refresh doesn't bust the Grype layer and vice-versa. The DB content is
# sourced via the scanner's own update flow (Trivy: ghcr.io/aquasecurity/
# trivy-db OCI; Grype: grype.anchore.io listing) so we always bake what
# the installed binary version expects.
#
# The DBs live at /opt/sensor/db/{trivy,grype} (read-only, layer-resident).
# /workspace/cache is hydrated from this path by /usr/local/bin/sensor-init.sh
# before the sensor binary runs, so scanners get a writable cache without
# re-downloading.
RUN mkdir -p /opt/sensor/db/trivy /opt/sensor/db/grype \
  && TRIVY_CACHE_DIR=/opt/sensor/db/trivy trivy image --download-db-only \
  # Bake Trivy's Java index DB alongside the vuln DB. Trivy refuses to
  # honor TRIVY_SKIP_JAVA_DB_UPDATE on first run when the java-db cache
  # is empty: it will hit FATAL `'--skip-java-db-update' cannot be
  # specified on the first run` and exit 1 even if the scanned image has
  # no Java content. Observed in the May 2026 staging soak (3 of 8 scans
  # failed this way under HG_DB_DIRECT_READ=1, where the cache dir is
  # the read-only baked path and first-run download is impossible).
  # Baking it adds ~10MB and removes the failure mode entirely.
  && TRIVY_CACHE_DIR=/opt/sensor/db/trivy trivy image --download-java-db-only

RUN GRYPE_DB_CACHE_DIR=/opt/sensor/db/grype grype db update

# Binary (placed late so daily DB-only refreshes don't bust the binary
# layer's cache — though our CI rebuilds top-down, this is still the
# correct ordering for any local incremental builds).
COPY --from=builder /harborguard-sensor /usr/local/bin/harborguard-sensor

# Init script hydrates /workspace/cache (or $HG_SCRATCH_DIR) from the
# baked /opt/sensor/db tree, then execs the sensor.
COPY scripts/sensor-init.sh /usr/local/bin/sensor-init.sh
RUN chmod +x /usr/local/bin/sensor-init.sh

# tini reaps zombies (e.g. fuse-overlayfs daemons reparented to PID 1
# when buildah exits) and forwards signals to the sensor. sensor-init.sh
# does the DB hydration then exec's the real binary.
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/sensor-init.sh", "harborguard-sensor"]
CMD ["agent"]
