# Stage 1: build mount-proxy-server from alibaba-cloud-csi-driver source
FROM golang:1.23 AS builder
RUN git clone https://github.com/kubernetes-sigs/alibaba-cloud-csi-driver.git /src && \
    cd /src && \
    git checkout feat/common-fuse && \
    CGO_ENABLED=0 go build -o /out/csi-mount-proxy-server ./cmd/mount-proxy-server

# Stage 2: JuiceFS client + mount-proxy + entrypoint
FROM juicedata/mount:latest

# Copy mount-proxy-server binary
COPY --from=builder /out/csi-mount-proxy-server /usr/local/bin/

# Copy JuiceFS entrypoint script
COPY entrypoint-juicefs.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# PID 1: mount-proxy-server listens for mount requests and runs /entrypoint.sh
ENTRYPOINT ["csi-mount-proxy-server", "--driver=customfuse"]
