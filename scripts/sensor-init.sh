#!/bin/sh
# sensor-init.sh — hydrate runtime scanner DB caches from the baked layer.
#
# At build time the Dockerfile pre-downloads Trivy + Grype databases into
# /opt/sensor/db/{trivy,grype}. Those paths are read-only and shared across
# the multi-stage rootfs. Scanners want a writable cache dir so they can
# update metadata and (if needed) fetch deltas. We hydrate the runtime
# cache here, before exec'ing the sensor.
#
# Two modes, gated by HG_SCRATCH_DIR:
#   unset (default) — hydrate to /workspace/cache and read from rootfs-backed dir
#   set (e.g. /dev/shm/sensor) — copy to tmpfs for hot reads
#
# Failure semantics: the hydration is best-effort. If the baked layer is
# missing (e.g. local dev image built without DBs), or the destination is
# already populated (re-exec from a recovered Fly Machine), we no-op and
# defer to the agent's own warmupScannerDBs() fallback.

set -eu

BAKED_TRIVY="/opt/sensor/db/trivy"
BAKED_GRYPE="/opt/sensor/db/grype"

# Resolve runtime cache root.
if [ -n "${HG_SCRATCH_DIR:-}" ]; then
    CACHE_ROOT="$HG_SCRATCH_DIR"

    # If scratch lives on tmpfs, ensure there's enough headroom. Trivy
    # unpacked is ~1G, Grype ~1.5G — require 4G free to leave slack for
    # scanner working files. Fail loudly rather than silently spilling
    # to swap or running OOM mid-scan.
    case "$CACHE_ROOT" in
        /dev/shm/*|/dev/shm)
            avail_kb=$(df -Pk /dev/shm | awk 'NR==2 {print $4}')
            avail_mb=$((avail_kb / 1024))
            if [ "$avail_mb" -lt 4096 ]; then
                echo "[sensor-init] ERROR: /dev/shm has ${avail_mb}MB free, need >=4096MB. Mount tmpfs with --shm-size=8g or unset HG_SCRATCH_DIR." >&2
                exit 1
            fi
            echo "[sensor-init] tmpfs /dev/shm has ${avail_mb}MB free (>=4096MB required)" >&2
            ;;
    esac
else
    # Default: keep the historical /workspace/cache path so anything
    # parsing logs or paths from the prior baked-DB rollout still works.
    CACHE_ROOT="/workspace/cache"
fi

mkdir -p "$CACHE_ROOT/trivy" "$CACHE_ROOT/grype"

hydrate() {
    src="$1"
    dst="$2"
    label="$3"

    if [ ! -d "$src" ] || [ -z "$(ls -A "$src" 2>/dev/null)" ]; then
        echo "[sensor-init] $label: baked DB missing at $src — agent warmup will fetch on demand" >&2
        return 0
    fi

    # Idempotent: if dst already has *files* (not just empty subdirs created
    # by Dockerfile mkdir -p), leave it. Re-execs (Fly Machine restart
    # preserving the rootfs) shouldn't pay the copy again. We use `find`
    # rather than `ls -A` because the Dockerfile pre-creates empty subdirs
    # like /workspace/cache/trivy/db that would otherwise look "populated".
    if [ -n "$(find "$dst" -type f 2>/dev/null | head -n 1)" ]; then
        echo "[sensor-init] $label: cache already populated at $dst, skipping copy" >&2
        return 0
    fi

    start=$(date +%s)
    # cp -a preserves perms; trailing /. copies contents not the dir itself.
    cp -a "$src/." "$dst/"
    end=$(date +%s)
    bytes=$(du -sb "$dst" 2>/dev/null | awk '{print $1}')
    mb=$((bytes / 1024 / 1024))
    echo "[sensor-init] $label: hydrated ${mb}MB from $src to $dst in $((end - start))s" >&2
}

hydrate "$BAKED_TRIVY" "$CACHE_ROOT/trivy" "trivy"
hydrate "$BAKED_GRYPE" "$CACHE_ROOT/grype" "grype"

export TRIVY_CACHE_DIR="$CACHE_ROOT/trivy"
export GRYPE_DB_CACHE_DIR="$CACHE_ROOT/grype"

exec "$@"
