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

# s3fs entrypoint for OpenKruise customfuse csi-sidecar
#
# Environment variables injected by mount-proxy-server from CSI request:
#   $source       — S3 bucket to mount ("s3://ml-datasets" or bare bucket name)
#   $url          — S3-compatible endpoint URL (MinIO, Alibaba OSS, Ceph RGW, ...)
#   $mountpoint   — target mount path inside the sandbox
#   $access_key   — object storage access key (from Secret)
#   $secret_key   — object storage secret key (from Secret)
#   $readOnly     — "true" or "false"
#   $otherOpts    — extra options from PV.Spec.VolumeAttributes
#
# Unlike the JuiceFS entrypoint there is no format step and no metadata
# engine: s3fs mounts an S3 bucket directly. Only the bucket root is
# mounted; sub-bucket prefixes are not supported.

# Credentials may be embedded in endpoint URLs (http://user:pass@host),
# never echo them.
mask_url() {
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
    # Debug options make s3fs print full HTTP headers — including the
    # Authorization signature — to stderr, which mount-proxy forwards to
    # logs. A volume never legitimately needs them, so deny them outright.
    for _opt in "${_OPTS[@]}"; do
        case "${_opt%%=*}" in
            curldbg|dbg|dbglevel|debug|verbose)
                echo "ERROR: debug option $_opt is not allowed (would leak credentials into logs)" >&2
                exit 1 ;;
        esac
    done
fi

# 1. Validate all inputs before any credential material is written to disk
# 1a. Credentials are required for s3fs
if [ -z "$access_key" ] || [ -z "$secret_key" ]; then
    echo "ERROR: access_key and secret_key are required for s3fs" >&2
    exit 1
fi

# 1a2. A newline in either credential would inject an extra line into the
# s3fs passwd file, silently corrupting authentication.
case "$access_key$secret_key" in
    *$'\n'*|*$'\r'*)
        echo "ERROR: credentials must not contain newlines" >&2
        exit 1 ;;
esac

# 1b. source must be "s3://bucket" or a bare bucket name. Any other URL
# form (redis://, http://user:pass@host, ...) is not an S3 bucket and may
# embed credentials that would leak into logs or the mount attempt.
case "$source" in
    s3://*) ;; # canonical form
    *://*)
        echo "ERROR: source must be 's3://bucket' or a bare bucket name: $(mask_url "$source")" >&2
        exit 1 ;;
esac

# 1c. Resolve the bucket name: "s3://bucket" or a bare bucket name
BUCKET="${source#s3://}"
BUCKET="${BUCKET%/}"
if [ -z "$BUCKET" ]; then
    echo "ERROR: source must name an S3 bucket (e.g. s3://ml-datasets)" >&2
    exit 1
fi

# 1d. mountpoint is injected by mount-proxy; guard against a missing value
# so the failure is readable instead of an s3fs usage message.
if [ -z "$mountpoint" ]; then
    echo "ERROR: mountpoint is empty" >&2
    exit 1
fi

# 1e. url is embedded into the comma-separated -o options, so whitespace
# would split options and break the mount. Reject it up front.
case "$url" in
    *[[:space:]]*)
        echo "ERROR: url must not contain whitespace: $(mask_url "$url")" >&2
        exit 1 ;;
esac

# 2. s3fs reads credentials from a passwd file in "accesskey:secretkey"
# format. The file stays for the mount's lifetime (s3fs may re-read it on
# reload); it lives in the container's private /tmp and disappears on
# restart.
umask 077
PASSWD_FILE="$(mktemp)"
trap 'rm -f "$PASSWD_FILE"' EXIT
printf '%s:%s\n' "$access_key" "$secret_key" > "$PASSWD_FILE"

# 3. Build mount options
# s3fs stays in foreground via -f below so mount-proxy can track the process.
# (The `foreground` option is rejected by newer libfuse, do not add it back.)
# allow_other: let business containers access the mount
# use_path_request_style: required by MinIO and other IP-addressed endpoints
MOUNT_OPTS="passwd_file=${PASSWD_FILE},allow_other,use_path_request_style"

# Endpoint
[ -n "$url" ] && MOUNT_OPTS="${MOUNT_OPTS},url=${url}"

# Read-only
[ "$readOnly" = "true" ] && MOUNT_OPTS="${MOUNT_OPTS},ro"

# User-specified extra options
[ -n "$otherOpts" ] && MOUNT_OPTS="${MOUNT_OPTS},${otherOpts}"

# 4. Mount
URL_LOG=""
[ -n "$url" ] && URL_LOG=" url=$(mask_url "$url")"
# Bucket is masked as a final line of defense even though source was
# validated above, in case a future validation change relaxes the charset.
echo "Mounting s3fs: bucket=$(mask_url "$BUCKET")${URL_LOG} mountpoint=$mountpoint"
exec s3fs "$BUCKET" "$mountpoint" -o "$MOUNT_OPTS" -f
