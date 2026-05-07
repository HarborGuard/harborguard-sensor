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
#
# JuiceFS mount mode (HG_JUICEFS_META set):
#   Mount a remote JuiceFS share at /opt/sensor/db (or HG_JUICEFS_MOUNT) and
#   then force HG_DB_DIRECT_READ=1 so the next branch reads scanner DBs
#   directly from the FUSE mount. Requires /dev/fuse (exposed on Fly
#   Firecracker; CONFIG_FUSE_FS=y on 6.12.47-fly). On stock Docker hosts,
#   `--cap-add SYS_ADMIN --security-opt apparmor=unconfined` is *additionally*
#   needed because `fusermount3` is gated by Linux apparmor + the default
#   seccomp profile; Fly Firecracker has neither, so /dev/fuse alone suffices
#   there. Mount failure is fatal — exit non-zero rather than fall through
#   to "no DB" mode which would silently produce empty scans.

set -eu

BAKED_TRIVY="/opt/sensor/db/trivy"
BAKED_GRYPE="/opt/sensor/db/grype"

# ---------------------------------------------------------------------------
# Mode 3: JuiceFS mount the DB tree, then fall through to direct-read.
# Runs first so a populated mount satisfies the direct-read baked-DB checks.
# Replaces the older NFS-mount path (Ganesha-on-Fly returns EIO on every
# NFSv4 READ — see deploy-sme P1 RCA). JuiceFS direct-FUSE clears the
# throughput bar (~150 MB/s vs Fly's 8 MB/s rootfs throttle).
# ---------------------------------------------------------------------------
if [ -n "${HG_JUICEFS_META:-}" ]; then
    JFS_MOUNT="${HG_JUICEFS_MOUNT:-/opt/sensor/db}"
    # JuiceFS native tunables. These are CLI flags on `juicefs mount`,
    # NOT kernel FUSE options — passing them via `-o` would route them to
    # fusermount3 and fail with "unknown option". Defaults are tuned for
    # cold-cache scanner reads: large attr/entry/dir caches (DB metadata
    # is effectively immutable for the lifetime of a scan), 2 GB on-disk
    # block cache, 16-block prefetch, 512 MB upload buffer.
    #
    # Override individually with these env vars; unset → use default.
    JFS_ATTR_CACHE="${HG_JUICEFS_ATTR_CACHE:-600}"
    JFS_ENTRY_CACHE="${HG_JUICEFS_ENTRY_CACHE:-600}"
    JFS_DIR_ENTRY_CACHE="${HG_JUICEFS_DIR_ENTRY_CACHE:-600}"
    JFS_CACHE_SIZE="${HG_JUICEFS_CACHE_SIZE:-2048}"
    JFS_PREFETCH="${HG_JUICEFS_PREFETCH:-16}"
    JFS_BUFFER_SIZE="${HG_JUICEFS_BUFFER_SIZE:-512}"
    # Kernel-level FUSE options forwarded to fusermount3 via `-o`. Default
    # empty — only set HG_JUICEFS_FUSE_OPTS when you need things like
    # `allow_other` for cross-uid access.
    JFS_FUSE_OPTS="${HG_JUICEFS_FUSE_OPTS:-}"
    # Redact creds in the URL when logging — meta URLs commonly carry
    # `redis://default:<password>@host:6379/0`. We log only the scheme+host.
    JFS_META_REDACTED=$(printf '%s' "$HG_JUICEFS_META" | sed -E 's#^([a-z0-9+]+)://[^@/]*@#\1://***@#')
    echo "[sensor-init] mounting juicefs ${JFS_META_REDACTED} -> ${JFS_MOUNT} (cache=${JFS_CACHE_SIZE}M prefetch=${JFS_PREFETCH} buffer=${JFS_BUFFER_SIZE}M attr=${JFS_ATTR_CACHE}s)" >&2
    mkdir -p "$JFS_MOUNT"
    # Build the juicefs invocation. Conditional `-o $JFS_FUSE_OPTS` is the
    # only optional piece — kept inline so we don't trample on $@ (the
    # caller's exec args, used at the bottom of this script).
    # NOTE on --read-only: bbolt (the BoltDB used by trivy.db) issues
    # flock(LOCK_SH) unconditionally on Open, even with ReadOnly=true. A
    # JuiceFS `--read-only` mount surfaces flock as EROFS, which trivy
    # reports as "failed to open db: read-only file system". The same
    # pathology was hit with NFS RO exports in P1.4. Solution: mount RW
    # at the FS layer; the *write protection* comes from the upstream
    # JuiceFS share being a read-only role/credential at the metadata
    # tier, plus our scanner-side air-gap env vars (TRIVY_SKIP_DB_UPDATE
    # etc.) which prevent any write attempts to begin with.
    if [ -n "$JFS_FUSE_OPTS" ]; then
        juicefs mount -d \
            --attr-cache "$JFS_ATTR_CACHE" \
            --entry-cache "$JFS_ENTRY_CACHE" \
            --dir-entry-cache "$JFS_DIR_ENTRY_CACHE" \
            --cache-size "$JFS_CACHE_SIZE" \
            --prefetch "$JFS_PREFETCH" \
            --buffer-size "$JFS_BUFFER_SIZE" \
            -o "$JFS_FUSE_OPTS" \
            "$HG_JUICEFS_META" "$JFS_MOUNT" \
            || { echo "[sensor-init] ERROR: juicefs mount failed; aborting (need /dev/fuse + reachable metadata)" >&2; exit 1; }
    else
        juicefs mount -d \
            --attr-cache "$JFS_ATTR_CACHE" \
            --entry-cache "$JFS_ENTRY_CACHE" \
            --dir-entry-cache "$JFS_DIR_ENTRY_CACHE" \
            --cache-size "$JFS_CACHE_SIZE" \
            --prefetch "$JFS_PREFETCH" \
            --buffer-size "$JFS_BUFFER_SIZE" \
            "$HG_JUICEFS_META" "$JFS_MOUNT" \
            || { echo "[sensor-init] ERROR: juicefs mount failed; aborting (need /dev/fuse + reachable metadata)" >&2; exit 1; }
    fi
    # juicefs -d returns once the mount is registered with the kernel,
    # but the FUSE handshake can still be in-flight. Block until the
    # mountpoint is actually populated (or we time out).
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if mountpoint -q "$JFS_MOUNT" 2>/dev/null; then
            break
        fi
        sleep 1
    done
    if ! mountpoint -q "$JFS_MOUNT" 2>/dev/null; then
        echo "[sensor-init] ERROR: juicefs mount did not register at $JFS_MOUNT after 10s" >&2
        exit 1
    fi
    echo "[sensor-init] juicefs mount ok: $(ls "$JFS_MOUNT" 2>/dev/null | tr '\n' ' ')" >&2

    # ---------------------------------------------------------------------
    # Open-with-retry shim — mitigates the atomic-flip ENOENT race.
    #
    # The daily refresh cron does sequential `mv -T` renames per scanner DB
    # tree (see harborguard-sensor refresh.sh: live -> .old, .next -> live).
    # Between the two renames there is a sub-millisecond window where
    # /opt/sensor/db/trivy or /opt/sensor/db/grype does not exist as a
    # directory entry. A scanner that does open() during that window gets
    # ENOENT. Already-open fds survive (POSIX unlink-while-open semantics
    # + JuiceFS .trash/ retention; validated in P1.5 Task D).
    #
    # We can't eliminate the rename window without a content-addressed
    # layout (out of scope for Phase 3). Instead we soak the start-of-scan
    # ENOENT here: if the canonical DB files aren't readable yet, retry up
    # to 5 × 50ms = 250ms total. The audit recommended 3 × 50ms (150ms);
    # I chose 5 for a slightly more conservative ceiling (still trivial vs
    # a ~50s scan) — bumps "effectively zero" failure rate to "even less".
    #
    # Grype's DB lives under a *versioned* subdirectory ("6/" today,
    # bumps when grype bumps DB schema), so we find the actual file
    # instead of hardcoding the version.
    # ---------------------------------------------------------------------
    retry_open() {
        target="$1"
        name="$2"
        attempt=1
        while [ "$attempt" -le 5 ]; do
            if [ -r "$target" ]; then
                return 0
            fi
            echo "[sensor-init] $name not yet readable at $target (attempt $attempt/5); retrying in 50ms" >&2
            # busybox `sleep` accepts fractional seconds on Alpine 3.20.
            sleep 0.05
            attempt=$((attempt + 1))
        done
        echo "[sensor-init] ERROR: $name never became readable at $target after 5 retries (250ms)" >&2
        return 1
    }

    # Trivy DB path is stable: <mount>/trivy/db/trivy.db.
    retry_open "${JFS_MOUNT}/trivy/db/trivy.db" "trivy.db" || exit 1

    # Grype DB lives under <mount>/grype/<schema>/vulnerability.db. Discover
    # the schema dir at runtime — find returns the first match (there should
    # only be one current-schema dir on a freshly-flipped mount).
    grype_db=$(find "${JFS_MOUNT}/grype" -maxdepth 2 -name vulnerability.db -type f 2>/dev/null | head -n 1)
    if [ -z "$grype_db" ]; then
        # Could be mid-flip with grype/.next swap underway — retry-find once.
        sleep 0.05
        grype_db=$(find "${JFS_MOUNT}/grype" -maxdepth 2 -name vulnerability.db -type f 2>/dev/null | head -n 1)
    fi
    if [ -z "$grype_db" ]; then
        echo "[sensor-init] ERROR: grype vulnerability.db not found under ${JFS_MOUNT}/grype/<schema>/" >&2
        exit 1
    fi
    retry_open "$grype_db" "grype vulnerability.db" || exit 1

    export HG_DB_DIRECT_READ=1
fi

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
