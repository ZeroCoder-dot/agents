# Stage 1: build mount-proxy-server from alibaba-cloud-csi-driver source
# IMAGE_PREFIX overrides the Docker Hub prefix for environments without direct
# Docker Hub access (e.g. docker.1panel.live).
ARG IMAGE_PREFIX=docker.io
FROM ${IMAGE_PREFIX}/golang:1.23 AS builder-proxy
RUN git clone https://github.com/kubernetes-sigs/alibaba-cloud-csi-driver.git /src && \
    cd /src && \
    git checkout pr1722 && \
    CGO_ENABLED=0 go build -o /out/csi-mount-proxy-server ./cmd/mount-proxy-server

# Stage 2: build csi-sidecar-customfuse (CSI node server) from agents source.
# Build context must be the repository root.
FROM ${IMAGE_PREFIX}/golang:1.23 AS builder-sidecar
COPY go.mod go.sum ./
COPY cmd/csi-sidecar-customfuse ./cmd/csi-sidecar-customfuse
COPY pkg/agent-runtime/customfusesidecar ./pkg/agent-runtime/customfusesidecar
RUN CGO_ENABLED=0 go build -o /out/csi-sidecar-customfuse ./cmd/csi-sidecar-customfuse

# Stage 3: JuiceFS client + both binaries + entrypoint
FROM ${IMAGE_PREFIX}/juicedata/mount:latest

COPY --from=builder-proxy /out/csi-mount-proxy-server /usr/local/bin/
COPY --from=builder-sidecar /out/csi-sidecar-customfuse /usr/local/bin/

# Copy entrypoint (must be /entrypoint.sh — mount-proxy looks for this path)
COPY pkg/sidecar/juicefs/entrypoint-juicefs.sh /entrypoint.sh
# start.sh runs both processes: mount-proxy-server (mounter.sock) and the
# CSI node server (csi.sock).
COPY pkg/sidecar/start.sh /start.sh
RUN chmod +x /entrypoint.sh /start.sh

ENTRYPOINT ["/start.sh"]
