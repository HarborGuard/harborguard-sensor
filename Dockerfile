FROM golang:1.23-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /harborguard-sensor .

FROM alpine:3.20
WORKDIR /app

# Scanner binaries
RUN apk add --no-cache curl bash ca-certificates

# Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.69.3

# Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Syft
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Dockle
RUN curl -L "https://github.com/goodwithtech/dockle/releases/download/v0.4.15/dockle_0.4.15_Linux-64bit.tar.gz" | tar xz -C /usr/local/bin dockle

# Dive
RUN curl -L "https://github.com/wagoodman/dive/releases/download/v0.13.1/dive_0.13.1_linux_amd64.tar.gz" | tar xz -C /usr/local/bin dive

# OSV Scanner
RUN curl -L "https://github.com/google/osv-scanner/releases/download/v2.2.2/osv-scanner_linux_amd64" -o /usr/local/bin/osv-scanner && chmod +x /usr/local/bin/osv-scanner

# Binary
COPY --from=builder /harborguard-sensor /usr/local/bin/harborguard-sensor

# Workspace
RUN mkdir -p /workspace/cache /workspace/reports

ENV TRIVY_CACHE_DIR=/workspace/cache/trivy
ENV GRYPE_DB_CACHE_DIR=/workspace/cache/grype
ENV SYFT_CACHE_DIR=/workspace/cache/syft

ENTRYPOINT ["harborguard-sensor"]
CMD ["agent"]
