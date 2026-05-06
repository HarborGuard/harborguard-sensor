#!/bin/sh
# sensor-init.sh — hydrate runtime scanner DB caches from the baked layer,
# OR (HG_DB_DIRECT_READ=1) point scanners at the read-only baked dir directly.
#
# At build time the Dockerfile pre-downloads Trivy + Grype databases into
# /opt/sensor/db/{trivy,grype}. Those paths are read-only and shared across
# the multi-stage rootfs.
#
# Modes (selection priority: HG_DB_DIRECT_READ > HG_SCRATCH_DIR > default):
#   HG_DB_DIRECT_READ=1
#       Skip hydration entirely. Point TRIVY_CACHE_DIR / GRYPE_DB_CACHE_DIR
#       at the baked /opt/sensor/db tree. Set scanner "skip update" env vars
#       so scanners do not attempt to write into the read-only paths.
#       The skip-update env vars alone are the gating mechanism: scanners
#       won't attempt DB writes through them (verified locally), and Fly
#       machines don't grant CAP_SYS_ADMIN so a "defense in depth" RO bind
#       mount is not available anyway.
#   HG_SCRATCH_DIR=<path> (e.g. /dev/shm/sensor)
#       Hydrate to that path (typically tmpfs).
#   default
#       Hydrate to /workspace/cache (rootfs-backed).
#
# Failure semantics: hydration is best-effort (missing baked DB → no-op,
# defer to agent's warmupScannerDBs fallback). Direct-read mode is strict:
# if the baked DB is missing it errors out, since there's nothing to read.

set -eu

BAKED_TRIVY="/opt/sensor/db/trivy"
BAKED_GRYPE="/opt/sensor/db/grype"

# ---------------------------------------------------------------------------
# Mode 2: direct read from baked DB. No copy, no hydration.
# ---------------------------------------------------------------------------
if [ "${HG_DB_DIRECT_READ:-0}" = "1" ]; then
    if [ ! -d "$BAKED_TRIVY" ] || [ -z "$(ls -A "$BAKED_TRIVY" 2>/dev/null)" ]; then
        echo "[sensor-init] ERROR: HG_DB_DIRECT_READ=1 but $BAKED_TRIVY missing/empty" >&2
        exit 1
    fi
    if [ ! -d "$BAKED_GRYPE" ] || [ -z "$(ls -A "$BAKED_GRYPE" 2>/dev/null)" ]; then
        echo "[sensor-init] ERROR: HG_DB_DIRECT_READ=1 but $BAKED_GRYPE missing/empty" >&2
        exit 1
    fi

    export TRIVY_CACHE_DIR="$BAKED_TRIVY"
    export GRYPE_DB_CACHE_DIR="$BAKED_GRYPE"

    # Air-gap env vars: prevent the scanners from attempting DB updates that
    # would write into the read-only baked paths.
    #
    # Trivy v0.69.x:
    #   TRIVY_SKIP_DB_UPDATE        — skip vuln DB pull
    #   TRIVY_SKIP_JAVA_DB_UPDATE   — skip java index DB pull
    # Grype v0.x:
    #   GRYPE_DB_AUTO_UPDATE=false  — never check / fetch listing.json
    #   GRYPE_DB_VALIDATE_AGE=false — don't refuse to scan if DB is "stale"
    export TRIVY_SKIP_DB_UPDATE=true
    export TRIVY_SKIP_JAVA_DB_UPDATE=true
    export GRYPE_DB_AUTO_UPDATE=false
    export GRYPE_DB_VALIDATE_AGE=false

    # Tell the agent the DB is "present" so warmupScannerDBs no-ops. Its
    # check is dbDirHasContent() on the cache dir, which the baked path
    # satisfies. Nothing extra needed.

    echo "[sensor-init] direct-read: TRIVY_CACHE_DIR=$TRIVY_CACHE_DIR GRYPE_DB_CACHE_DIR=$GRYPE_DB_CACHE_DIR (no hydration)" >&2
    exec "$@"
fi

# ---------------------------------------------------------------------------
# Modes 0 / 1: hydrate to writable cache dir.
# ---------------------------------------------------------------------------

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
