# Stage 1: build mount-proxy-server from alibaba-cloud-csi-driver source
# IMAGE_PREFIX overrides the Docker Hub prefix for environments without direct
# Docker Hub access (e.g. docker.1panel.live).
ARG IMAGE_PREFIX=docker.io
# pr-1722's go.mod requires go >= 1.26.0; the sidecar stage below keeps
# 1.25 because this repo's go.mod only requires >= 1.25.0.
# GOPROXY is pinned to a mainland mirror: proxy.golang.org is unreachable or
# extremely slow from China, which stalls the module download step.
FROM ${IMAGE_PREFIX}/golang:1.26 AS builder-proxy
ENV GOPROXY=https://goproxy.cn,direct
# Source arrives via the proxy-src build context (docker build
# --build-context proxy-src=<local checkout>): cloning GitHub inside the
# build container fails on networks that only allow proxied egress. The
# original pin (d45ddfa) was force-pushed out of pr-1722's history, so the
# build now checks the checkout against the current pr-1722 HEAD instead —
# the test fails the build if the local checkout ever drifts.
COPY --from=proxy-src / /src
WORKDIR /src
RUN test "$(git rev-parse HEAD)" = "6e1d6281616d8486287845959272f873ab72fa07" && \
    CGO_ENABLED=0 go build -o /out/csi-mount-proxy-server ./cmd/mount-proxy-server

# Stage 2: build csi-sidecar-customfuse (CSI node server) from agents source.
# Build context must be the repository root.
# go.mod requires go >= 1.25.0.
FROM ${IMAGE_PREFIX}/golang:1.25 AS builder-sidecar
ENV GOPROXY=https://goproxy.cn,direct
COPY go.mod go.sum ./
COPY cmd/csi-sidecar-customfuse ./cmd/csi-sidecar-customfuse
COPY pkg/agent-runtime/customfusesidecar ./pkg/agent-runtime/customfusesidecar
RUN CGO_ENABLED=0 go build -o /out/csi-sidecar-customfuse ./cmd/csi-sidecar-customfuse

# Stage 3: s3fs FUSE client + both binaries + entrypoint
FROM ${IMAGE_PREFIX}/ubuntu:22.04

# Use Aliyun mirror so apt works without direct access to archive.ubuntu.com.
RUN sed -i -e 's|archive.ubuntu.com|mirrors.aliyun.com|g' -e 's|security.ubuntu.com|mirrors.aliyun.com|g' /etc/apt/sources.list && \
    apt-get update && apt-get install -y --no-install-recommends \
        s3fs fuse3 ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

# allow_other: s3fs requires explicit opt-in in fuse.conf.
# The container runs as root so this is belt-and-braces.
RUN echo "user_allow_other" >> /etc/fuse.conf

COPY --from=builder-proxy /out/csi-mount-proxy-server /usr/local/bin/
COPY --from=builder-sidecar /out/csi-sidecar-customfuse /usr/local/bin/

# Copy entrypoint (must be /entrypoint.sh — mount-proxy looks for this path)
COPY pkg/sidecar/s3fs/entrypoint-s3fs.sh /entrypoint.sh
# start.sh runs both processes: mount-proxy-server (mounter.sock) and the
# CSI node server (csi.sock).
COPY pkg/sidecar/start.sh /start.sh
RUN chmod +x /entrypoint.sh /start.sh

ENTRYPOINT ["/start.sh"]
