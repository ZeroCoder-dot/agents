#!/bin/bash
set -e

# Defense in depth: mount-proxy exports every Secret entry as an environment
# variable of the same name, so a Secret key could smuggle a code-execution
# env var (BASH_ENV, LD_PRELOAD, ...) into this shell. The provider rejects
# these keys, but clear them here too so a future relaxation cannot silently
# reintroduce the attack. PATH is reset to the image default because an
# injected PATH would shadow command lookup.
unset BASH_ENV ENV BASHOPTS SHELLOPTS PROMPT_COMMAND PS4 IFS BASH_XTRACEFD \
      LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_BIND_NOW LD_DEBUG \
      GLIBC_TUNABLES CDPATH HISTFILE 2>/dev/null || true
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# JuiceFS entrypoint for OpenKruise customfuse csi-sidecar
#
# Environment variables injected by mount-proxy-server from CSI request:
#   $source       — JuiceFS META-URL (e.g. redis://redis-cluster:6379/0)
#   $mountpoint   — target mount path inside the sandbox
#   $token        — JuiceFS token (from Secret, if present)
#   $access_key   — object storage access key (from Secret)
#   $secret_key   — object storage secret key (from Secret)
#   $bucket       — object storage bucket name
#   $url          — object storage URL
#   $storageType  — object storage type ("s3" default, "oss", "minio", ...)
#   $path         — sub-path under the volume root
#   $capacity     — volume capacity quota (e.g. "100Gi")
#   $readOnly     — "true" or "false"
#   $otherOpts    — extra options from PV.Spec.VolumeAttributes

# Log masking
# META-URLs may embed credentials (redis://user:pass@host), never echo them.
mask_source() {
    printf '%s' "$1" | sed -E 's|(://)[^ ]*@|\1***@|'
}

# Shell injection prevention
validate_opts() {
    for opt in "$@"; do
        if [[ "$opt" =~ [\;\|\&\`\$\(\)$'\n'$'\r'] ]]; then
            echo "ERROR: invalid character in option: $opt" >&2
            exit 1
        fi
    done
}
if [ -n "$otherOpts" ]; then
    IFS=' ' read -ra _OPTS <<< "$otherOpts"
    validate_opts "${_OPTS[@]}"
    # Debug options make the FUSE client print full request details —
    # including Authorization signatures and credential material — to
    # stderr, which mount-proxy forwards to logs. A volume never
    # legitimately needs them, so deny them outright.
    for _opt in "${_OPTS[@]}"; do
        case "${_opt%%=*}" in
            curldbg|dbg|dbglevel|debug|verbose)
                echo "ERROR: debug option $_opt is not allowed (would leak credentials into logs)" >&2
                exit 1 ;;
        esac
    done
fi

# 1. Auth
# Token mode: authenticate with JuiceFS token
# Static AK/SK mode: authenticate via --access-key/--secret-key in juicefs format
FORMAT_ARGS=()

if [ -n "$token" ]; then
    export JFS_TOKEN="$token"
fi

if [ -n "$access_key" ] && [ -n "$secret_key" ]; then
    FORMAT_ARGS+=(--access-key="$access_key" --secret-key="$secret_key")
fi

# 2. Format (first-time only, safe to re-run)
# juicefs requires the object storage parameters when formatting a new
# volume; they arrive from PV volumeAttributes as $bucket/$url/$storageType.
if [ ${#FORMAT_ARGS[@]} -gt 0 ]; then
    if [ -z "$bucket" ]; then
        echo "ERROR: bucket is required for object storage format" >&2
        exit 1
    fi
    FORMAT_ARGS+=(--storage="${storageType:-s3}" --bucket="$bucket")
    [ -n "$url" ] && FORMAT_ARGS+=(--endpoint="$url")
    echo "Formatting volume: $(mask_source "$source") storage=${storageType:-s3} bucket=$bucket"
    juicefs format "${FORMAT_ARGS[@]}" "$source" myjfs
fi

# 3. Credential cleanup
unset access_key secret_key token JFS_TOKEN

# 4. Build mount options
# foreground: FUSE stays in foreground so mount-proxy can track the process
# no-update: skip JuiceFS version check (version pinned by container image)
MOUNT_OPTS="foreground,no-update"

# Read-only
[ "$readOnly" = "true" ] && MOUNT_OPTS="${MOUNT_OPTS},ro"

# User-specified extra options
[ -n "$otherOpts" ] && MOUNT_OPTS="${MOUNT_OPTS},${otherOpts}"

# 5. Set quota (optional)
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

# 6. Mount
# $path mounts a sub-directory as the volume root via --subdir. It is passed
# as an argv argument, never interpolated into -o, so it has no shell
# injection surface; its character set is already enforced by the provider.
MOUNT_ARGS=()
[ -n "$path" ] && MOUNT_ARGS+=(--subdir="$path")
echo "Mounting JuiceFS: source=$(mask_source "$source") mountpoint=$mountpoint options=$MOUNT_OPTS subdir=${path:-/}"
exec mount.juicefs "$source" "$mountpoint" -o "$MOUNT_OPTS" "${MOUNT_ARGS[@]}"
