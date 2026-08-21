# Stage 1: build mount-proxy-server from alibaba-cloud-csi-driver source
# IMAGE_PREFIX overrides the Docker Hub prefix for environments without direct
# Docker Hub access (e.g. docker.1panel.live).
ARG IMAGE_PREFIX=docker.io
# PROXY_SRC_SHA pins the proxy-src checkout; override with --build-arg
# when the pr-1722 branch advances (after verifying compatibility).
ARG PROXY_SRC_SHA=6e1d6281616d8486287845959272f873ab72fa07
# GOPROXY defaults to a mainland mirror; override with --build-arg
# for environments with other reachable proxies.
ARG GOPROXY=https://goproxy.cn,direct
# pr-1722's go.mod requires go >= 1.26.0; the sidecar stage below uses
# 1.26 as well because this repo's go.mod requires >= 1.25.9.
FROM ${IMAGE_PREFIX}/golang:1.26 AS builder-proxy
ARG PROXY_SRC_SHA
ARG GOPROXY
ENV GOPROXY=${GOPROXY}
# Source arrives via the proxy-src build context (docker build
# --build-context proxy-src=<local checkout>): cloning GitHub inside the
# build container fails on networks that only allow proxied egress. The
# original pin (d45ddfa) was force-pushed out of pr-1722's history, so the
# build now checks the checkout against the current pr-1722 HEAD instead —
# the test fails the build if the local checkout ever drifts. The context
# must be a real git checkout (archive/tarball exports lack .git and fail
# the HEAD check); the explicit test turns that into a clear error. The RUN
# step also detects worktrees explicitly: it resolves the gitdir named by
# a .git file and fails with a clear error when the target is not resolvable
# inside the build container. Use the main checkout, not a worktree: a
# worktree's .git file points back
# at the main repository and cannot resolve inside the build container.
COPY --from=proxy-src / /src
WORKDIR /src
RUN { test -d .git || test -f .git; } || { echo "ERROR: proxy-src build context must be a git checkout with .git" >&2; exit 1; } && \
    if [ -f .git ]; then _gitdir=$(sed -n 's|^gitdir: ||p' .git); test -d "$_gitdir" || { echo "ERROR: proxy-src is a worktree (gitdir $_gitdir not resolvable in the build container); use the main checkout" >&2; exit 1; }; fi && \
    test "$(git rev-parse HEAD)" = "${PROXY_SRC_SHA}" && \
    CGO_ENABLED=0 go build -o /out/csi-mount-proxy-server ./cmd/mount-proxy-server

# Stage 2: build csi-sidecar-customfuse (CSI node server) from agents source.
# Build context must be the repository root.
# !!! Run the build from the repository root, e.g.:
# !!! docker buildx build --build-context proxy-src=<csi-driver checkout> -f pkg/sidecar/.../Dockerfile -t <image> .
# go.mod requires go >= 1.25.9; the 1.26 image satisfies it and matches the
# builder-proxy stage above.
FROM ${IMAGE_PREFIX}/golang:1.26 AS builder-sidecar
ARG GOPROXY
ENV GOPROXY=${GOPROXY}
COPY go.mod go.sum ./
COPY cmd/csi-sidecar-customfuse ./cmd/csi-sidecar-customfuse
COPY pkg/agent-runtime/customfusesidecar ./pkg/agent-runtime/customfusesidecar
# customfusesidecar imports customfusevalidate; omit it and the build
# fails. Keep this COPY set in sync with the packages customfusesidecar
# imports whenever a new in-repo dependency is added.
COPY pkg/agent-runtime/customfusevalidate ./pkg/agent-runtime/customfusevalidate
RUN CGO_ENABLED=0 go build -o /out/csi-sidecar-customfuse ./cmd/csi-sidecar-customfuse

# Stage 3: s3fs FUSE client + both binaries + entrypoint
# Pinned by digest for reproducible builds, mirroring the juicefs
# Dockerfile; do not float on the :22.04 tag. The digest is amd64-only.
FROM ${IMAGE_PREFIX}/ubuntu:22.04@sha256:3c3de9608507804525ff4303874525760ea36d62606e8105f515adaa761b80cb

# Use Aliyun mirror so apt works without direct access to archive.ubuntu.com.
# s3fs is version-pinned: the base image digest fixes the initial state
# but apt would otherwise install whatever the repo currently carries.
RUN sed -i -e 's|archive.ubuntu.com|mirrors.aliyun.com|g' -e 's|security.ubuntu.com|mirrors.aliyun.com|g' /etc/apt/sources.list && \
    apt-get update && apt-get install -y --no-install-recommends \
        s3fs=1.90-1 fuse3 ca-certificates && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# allow_other: s3fs requires explicit opt-in in fuse.conf.
# The container runs as root so this is belt-and-braces. printf (not echo
# >>) so the entry still parses if the packaged file lacked a trailing
# newline.
RUN printf '\nuser_allow_other\n' >> /etc/fuse.conf

COPY --from=builder-proxy /out/csi-mount-proxy-server /usr/local/bin/
COPY --from=builder-sidecar /out/csi-sidecar-customfuse /usr/local/bin/
# go build outputs already carry the executable bit; the explicit chmod is
# belt-and-braces for COPY paths that lose file modes.
RUN chmod +x /usr/local/bin/csi-mount-proxy-server /usr/local/bin/csi-sidecar-customfuse

# Copy entrypoint (must be /entrypoint.sh — mount-proxy looks for this path)
COPY pkg/sidecar/s3fs/entrypoint-s3fs.sh /entrypoint.sh
# start.sh runs both processes: mount-proxy-server (mounter.sock) and the
# CSI node server (csi.sock).
COPY pkg/sidecar/start.sh /start.sh
RUN chmod +x /entrypoint.sh /start.sh

ENTRYPOINT ["/start.sh"]
