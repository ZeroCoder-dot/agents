#!/bin/sh
# Starts both processes of the csi-sidecar-customfuse image:
#   - csi-mount-proxy-server: listens on /var/run/csi/mounter.sock, runs
#     /entrypoint.sh for each mount (s3fs/juicefs FUSE mount)
#   - csi-sidecar-customfuse: CSI node server listening on the per-driver
#     csi.sock, forwards NodePublishVolume to mount-proxy-server
#
# The image runs as root (no USER directive), so /var/run/csi is always
# writable; if the image is ever converted to a non-root user, an explicit
# volume mount or directory pre-creation becomes necessary here.
set -e
mkdir -p /var/run/csi
csi-mount-proxy-server --driver=customfuse &
MPID=$!
csi-sidecar-customfuse &
SPID=$!
TERMINATING=0
# Forward termination signals to both children: the node server drains its
# gRPC server on SIGTERM, mount-proxy shuts down FUSE mounts cleanly.
trap 'TERMINATING=1; kill $MPID $SPID 2>/dev/null || true' TERM INT

# wait_for_exit waits for pid to terminate, escalating from SIGTERM to SIGKILL
# after 10 seconds so a stuck child cannot hang container shutdown past the
# Kubernetes grace period. The exit status of the child is returned, and wait
# reaps it so it cannot linger as a zombie in this PID space.
wait_for_exit() {
    _pid=$1
    _i=0
    while kill -0 $_pid 2>/dev/null; do
        _i=$((_i + 1))
        if [ $_i -ge 10 ]; then
            kill -9 $_pid 2>/dev/null || true
            break
        fi
        sleep 1
    done
    wait $_pid 2>/dev/null
    return $?
}

# Supervise both processes. If mount-proxy dies unexpectedly, take the whole
# container down so Kubernetes rebuilds the sandbox instead of silently
# degrading into "all new mounts fail". If the node server exits, take the
# proxy with it and propagate the exit status.
while :; do
    if ! kill -0 $MPID 2>/dev/null; then
        [ $TERMINATING -eq 0 ] && echo "csi-mount-proxy-server exited unexpectedly" >&2
        kill $SPID 2>/dev/null || true
        break
    fi
    if ! kill -0 $SPID 2>/dev/null; then
        break
    fi
    sleep 1
done

# Cleanup runs in if-context so set -e cannot abort the script before the
# other process is stopped and reaped when the node server exits non-zero.
if wait_for_exit $SPID; then
    STATUS=0
else
    STATUS=$?
fi
wait_for_exit $MPID || true
if [ $TERMINATING -eq 1 ]; then
    exit 0
fi
exit $STATUS
