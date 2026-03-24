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

# Scanner binaries + skopeo for registry image prefetch
RUN apk add --no-cache curl bash ca-certificates skopeo \
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

# Binary
COPY --from=builder /harborguard-sensor /usr/local/bin/harborguard-sensor

# Workspace
RUN mkdir -p /workspace/cache/trivy/db /workspace/cache/grype /workspace/cache/syft /workspace/reports

ENV TRIVY_CACHE_DIR=/workspace/cache/trivy
ENV GRYPE_DB_CACHE_DIR=/workspace/cache/grype
ENV SYFT_CACHE_DIR=/workspace/cache/syft

# Pre-bake scanner databases so containers start without cold-start downloads
RUN trivy image --download-db-only && grype db update

ENTRYPOINT ["harborguard-sensor"]
CMD ["agent"]
