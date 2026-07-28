#!/bin/bash
set -e

# ── JuiceFS entrypoint for OpenKruise customfuse csi-sidecar ──
#
# Environment variables injected by mount-proxy-server from CSI request:
#   $source       — JuiceFS META-URL (e.g. redis://redis-cluster:6379/0)
#   $mountpoint   — target mount path inside the sandbox
#   $token        — JuiceFS token (from Secret, if present)
#   $access-key   — object storage access key (from Secret)
#   $secret-key   — object storage secret key (from Secret)
#   $bucket       — object storage bucket name
#   $url          — object storage URL
#   $path         — sub-path under the volume root
#   $capacity     — volume capacity quota (e.g. "100Gi")
#   $readOnly     — "true" or "false"
#   $otherOpts    — extra options from PV.Spec.VolumeAttributes

# ── Shell injection prevention ──
validate_opts() {
    for opt in "$@"; do
        if [[ "$opt" =~ [\;\|\&\`\$\(\)$'\n'] ]]; then
            echo "ERROR: invalid character in option: $opt" >&2
            exit 1
        fi
    done
}
if [ -n "$otherOpts" ]; then
    IFS=' ' read -ra _OPTS <<< "$otherOpts"
    validate_opts "${_OPTS[@]}"
fi

# ── 1. Auth ──
# Token mode: authenticate with JuiceFS token
# Static AK/SK mode: authenticate via --access-key/--secret-key in juicefs format
FORMAT_ARGS=()

if [ -n "$token" ]; then
    export JFS_TOKEN="$token"
fi

if [ -n "$access-key" ] && [ -n "$secret-key" ]; then
    FORMAT_ARGS+=(--access-key="$access-key" --secret-key="$secret-key")
fi

# ── 2. Format (first-time only, safe to re-run) ──
if [ ${#FORMAT_ARGS[@]} -gt 0 ]; then
    echo "Formatting volume: $source"
    juicefs format "${FORMAT_ARGS[@]}" "$source" myjfs
fi

# ── 3. Credential cleanup ──
unset access-key secret-key token JFS_TOKEN

# ── 4. Build mount options ──
# foreground: FUSE stays in foreground so mount-proxy can track the process
# no-update: skip JuiceFS version check (version pinned by container image)
MOUNT_OPTS="foreground,no-update"

# Read-only
[ "$readOnly" = "true" ] && MOUNT_OPTS="${MOUNT_OPTS},ro"

# User-specified extra options
[ -n "$otherOpts" ] && MOUNT_OPTS="${MOUNT_OPTS},${otherOpts}"

# ── 5. Set quota (optional) ──
if [ -n "$capacity" ]; then
    case "$capacity" in
        *TiB|*Ti) capacity=$(( ${capacity%%[A-Za-z]*} * 1024 )) ;;
        *GiB|*Gi) capacity=${capacity%%[A-Za-z]*} ;;
        *MiB|*Mi) capacity=$(( ${capacity%%[A-Za-z]*} / 1024 )) ;;
        *[A-Za-z]*)
            echo "ERROR: unsupported capacity unit: $capacity" >&2
            exit 1 ;;
    esac
    echo "Setting JuiceFS quota: capacity=${capacity}GiB"
    juicefs quota set "$source" --path / --capacity "$capacity" || true
fi

# ── 6. Mount ──
echo "Mounting JuiceFS: source=$source mountpoint=$mountpoint options=$MOUNT_OPTS"
exec mount.juicefs "$source" "$mountpoint" -o "$MOUNT_OPTS"
