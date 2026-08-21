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

# Stage 3: JuiceFS client + both binaries + entrypoint
# Pinned by digest (Debian 12, bash 5.2.15 — start.sh requires bash >= 5.1
# for wait -n -p). Do not float on :latest: the build must stay
# reproducible and the upstream image updates JuiceFS client versions.
FROM ${IMAGE_PREFIX}/juicedata/mount@sha256:ee34645eae22378bfa7e9728210a243b32962971942ce52011cd08497cf38927

COPY --from=builder-proxy /out/csi-mount-proxy-server /usr/local/bin/
COPY --from=builder-sidecar /out/csi-sidecar-customfuse /usr/local/bin/
# go build outputs already carry the executable bit; the explicit chmod is
# belt-and-braces for COPY paths that lose file modes.
RUN chmod +x /usr/local/bin/csi-mount-proxy-server /usr/local/bin/csi-sidecar-customfuse

# Copy entrypoint (must be /entrypoint.sh — mount-proxy looks for this path)
COPY pkg/sidecar/juicefs/entrypoint-juicefs.sh /entrypoint.sh
# start.sh runs both processes: mount-proxy-server (mounter.sock) and the
# CSI node server (csi.sock).
COPY pkg/sidecar/start.sh /start.sh
RUN chmod +x /entrypoint.sh /start.sh

ENTRYPOINT ["/start.sh"]
