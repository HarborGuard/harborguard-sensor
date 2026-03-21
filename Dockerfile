FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine
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

# App
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

# Workspace
RUN mkdir -p /workspace/cache /workspace/reports

ENV TRIVY_CACHE_DIR=/workspace/cache/trivy
ENV GRYPE_DB_CACHE_DIR=/workspace/cache/grype
ENV SYFT_CACHE_DIR=/workspace/cache/syft

ENTRYPOINT ["node", "dist/index.js"]
CMD ["agent"]
