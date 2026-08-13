/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package customfusesidecar

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkruise/agents/pkg/agent-runtime/customfusevalidate"
)

// proxyMounter is the mount-proxy client surface used by the node server.
type proxyMounter interface {
	Mount(ctx context.Context, req *proxyMountRequest) error
}

// newProxyClientFn is the indirection used by the node server to obtain a
// proxy client. It is a package variable so tests can substitute a fake
// without binding to a real unix socket. Production code MUST NOT reassign
// it.
var newProxyClientFn = func(socketPath string) proxyMounter {
	return newProxyClient(socketPath)
}

// nodeServer implements csi.NodeServer for the customfuse driver inside the
// sandbox sidecar. It mounts directly on the target path (no global mount +
// bind), because the target already lives inside the sandbox mount namespace.
type nodeServer struct {
	csi.UnimplementedNodeServer

	locks         *volumeLocks
	proxySockPath string
}

// NewNodeServer returns a NodeServer that forwards mount requests to the
// mount-proxy-server listening on proxySockPath.
func NewNodeServer(proxySockPath string) csi.NodeServer {
	return &nodeServer{
		locks:         newVolumeLocks(),
		proxySockPath: proxySockPath,
	}
}

func (ns *nodeServer) NodeGetCapabilities(_ context.Context, _ *csi.NodeGetCapabilitiesRequest) (*csi.NodeGetCapabilitiesResponse, error) {
	return &csi.NodeGetCapabilitiesResponse{Capabilities: []*csi.NodeServiceCapability{
		{
			Type: &csi.NodeServiceCapability_Rpc{
				Rpc: &csi.NodeServiceCapability_RPC{
					Type: csi.NodeServiceCapability_RPC_STAGE_UNSTAGE_VOLUME,
				},
			},
		},
	}}, nil
}

func (ns *nodeServer) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	if !ns.locks.TryAcquire(req.GetVolumeId()) {
		return nil, status.Errorf(codes.Aborted, "There is already an operation for %s", req.GetVolumeId())
	}
	defer ns.locks.Release(req.GetVolumeId())

	targetPath := req.GetTargetPath()
	if err := validateTargetPath(targetPath); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	// In the standard CSI flow the kubelet creates the target path before
	// calling NodePublishVolume; the storage CLI does not, so create it here.
	if err := os.MkdirAll(targetPath, 0o750); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create target path: %v", err)
	}

	opts, err := parseOptions(req)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse options: %v", err)
	}
	if err := precheckAuthConfig(opts); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "auth config error: %v", err)
	}

	// The provider validates Secret keys and mount flags on the control-plane
	// path, but the per-driver unix socket is reachable from inside the
	// sandbox, so requests can arrive without passing through the provider.
	// mount-proxy exports every Secret entry and mount flag as an environment
	// variable of the same name into the entrypoint shell; repeat the checks
	// here because the entrypoint's own unset of dangerous keys happens too
	// late for its starting shell (bash sources BASH_ENV before the script
	// body, the loader consumes LD_PRELOAD before that).
	if err := customfusevalidate.ValidateSecrets(req.GetSecrets()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid secret: %v", err)
	}
	if volCap := req.GetVolumeCapability(); volCap != nil {
		if mount := volCap.GetMount(); mount != nil {
			if err := customfusevalidate.ValidateMountOptions(mount.MountFlags); err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "invalid mount flag: %v", err)
			}
		}
	}

	client := newProxyClientFn(ns.proxySockPath)
	if err := client.Mount(ctx, &proxyMountRequest{
		Source:  opts.Source,
		Target:  targetPath,
		Fstype:  customFuseFsType,
		Options: opts.makeMountOptions(),
		Secrets: req.GetSecrets(),
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "mount-proxy failed: %v", err)
	}

	return &csi.NodePublishVolumeResponse{}, nil
}

func (ns *nodeServer) NodeUnpublishVolume(_ context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	if !ns.locks.TryAcquire(req.GetVolumeId()) {
		return nil, status.Errorf(codes.Aborted, "There is already an operation for %s", req.GetVolumeId())
	}
	defer ns.locks.Release(req.GetVolumeId())

	// Unmounting is handled by the sandbox teardown: the mount namespace is
	// discarded together with the sandbox, so there is nothing to clean up
	// here. Accept the request to keep the CSI protocol happy.
	return &csi.NodeUnpublishVolumeResponse{}, nil
}

func (ns *nodeServer) NodeStageVolume(_ context.Context, _ *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {
	return &csi.NodeStageVolumeResponse{}, nil
}

func (ns *nodeServer) NodeUnstageVolume(_ context.Context, _ *csi.NodeUnstageVolumeRequest) (*csi.NodeUnstageVolumeResponse, error) {
	return &csi.NodeUnstageVolumeResponse{}, nil
}

// mountRootPrefix is the sandbox-wide directory that hosts every per-volume
// mount point. The storage CLI relocates the user-visible target to
// <mount-root>/<driver>/<md5> before calling NodePublishVolume, so a request
// whose target resolves outside it can only come from a direct socket caller
// trying to shadow arbitrary sidecar paths.
const mountRootPrefix = "/run/csi/mount-root/"

// validateTargetPath rejects empty, relative, null-byte-bearing, or
// mount-root-escaping target paths before they reach the entrypoint.
func validateTargetPath(targetPath string) error {
	if strings.TrimSpace(targetPath) == "" {
		return fmt.Errorf("target path is empty")
	}
	// path.IsAbs uses POSIX semantics, which is what the sandbox container
	// sees; filepath.IsAbs would treat "/..." as relative on Windows hosts.
	if !path.IsAbs(targetPath) {
		return fmt.Errorf("target path %q is not an absolute path", targetPath)
	}
	if strings.ContainsRune(targetPath, '\x00') {
		return fmt.Errorf("target path contains a null byte")
	}
	// path.Clean resolves ".." segments; the cleaned path must stay under the
	// mount root so a malicious request cannot mount over arbitrary sidecar
	// directories (e.g. "/run/../etc/x" -> "/etc/x").
	cleaned := path.Clean(targetPath)
	if !strings.HasPrefix(cleaned, mountRootPrefix) {
		return fmt.Errorf("target path %q is outside the mount root %s", targetPath, mountRootPrefix)
	}
	return nil
}

// volumeLocks serializes operations per volume id. TryAcquire fails instead
// of blocking so a concurrent request on the same volume is rejected fast.
type volumeLocks struct {
	mu    sync.Mutex
	holds map[string]struct{}
}

func newVolumeLocks() *volumeLocks {
	return &volumeLocks{holds: map[string]struct{}{}}
}

func (l *volumeLocks) TryAcquire(id string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.holds[id]; ok {
		return false
	}
	l.holds[id] = struct{}{}
	return true
}

func (l *volumeLocks) Release(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.holds, id)
}
