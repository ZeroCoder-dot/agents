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
	"fmt"
	"strings"
	"unicode"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/openkruise/agents/pkg/agent-runtime/customfusevalidate"
)

// fuseOptions are the parsed volume attributes of a customfuse volume.
// Field semantics follow the alibaba-cloud-csi-driver customfuse driver so
// entrypoints written for it behave identically here.
type fuseOptions struct {
	// Source is the mount source passed to the FUSE entrypoint as $source.
	// Its format is opaque to the CSI side — it can be a JuiceFS META-URL
	// (e.g. "redis://host:6379/1"), an OSS-style bucket:path, or any string
	// the entrypoint understands.
	Source string
	// Bucket is the object storage bucket name, passed as $bucket.
	Bucket string
	// URL is the object storage endpoint, passed as $url.
	URL string
	// OtherOpts originates from volumeAttributes.otherOpts, passed as
	// $otherOpts. An alternative to mountOptions — both are valid styles.
	OtherOpts string
	// Path is the sub-path within the volume, passed as $path.
	Path string
	// ReadOnly is derived from the CSI readOnly flag or the volume access
	// mode, passed as $readOnly to the entrypoint.
	ReadOnly bool
	// FuseType identifies the FUSE client for metrics labeling (e.g.
	// "juicefs", "jindo"). Defaults to "customfuse" when unset.
	FuseType string
	// MountOptions are from pv.Spec.MountOptions (via
	// VolumeCapability.Mount.MountFlags). Each entry is a "key=value" or
	// bare "key" string, passed as env var $key in the entrypoint.
	MountOptions []string
	// AuthType selects the authentication method. Only the default (empty)
	// is supported, which passes Secret entries directly as env vars.
	AuthType string
	// Capacity is the volume quota passed as $capacity to the entrypoint.
	// Plain integers pass through; values with units are validated as
	// Kubernetes Quantity.
	Capacity string
	// StorageType is the object storage backend passed as $storageType to the
	// entrypoint (e.g. "s3", "oss", "minio"). Only the JuiceFS entrypoint
	// consumes it, during format.
	StorageType string
}

// customFuseFsType is the fsType reported to mount-proxy; it selects the
// customfuse driver there.
const customFuseFsType = "customfuse"

// parseOptions converts a NodePublishVolumeRequest into fuseOptions. Keys in
// VolumeContext are matched case-insensitively after trimming.
func parseOptions(req *csi.NodePublishVolumeRequest) (*fuseOptions, error) {
	opts := &fuseOptions{
		FuseType: customFuseFsType,
	}

	for k, v := range req.GetVolumeContext() {
		key := strings.TrimSpace(strings.ToLower(k))
		value := strings.TrimSpace(v)
		if value == "" {
			continue
		}
		switch key {
		case "source":
			opts.Source = value
		case "bucket":
			opts.Bucket = value
		case "path":
			opts.Path = value
		case "url":
			opts.URL = value
		case "otheropts":
			opts.OtherOpts = value
		case "fusetype":
			opts.FuseType = value
		case "authtype":
			opts.AuthType = value
		case "capacity":
			if hasUnitSuffix(value) {
				if _, err := resource.ParseQuantity(value); err != nil {
					return nil, fmt.Errorf("invalid capacity %q: must be a plain integer or Kubernetes Quantity (e.g. 100, 100Gi): %v", customfusevalidate.MaskOptionValues(value), err)
				}
			}
			opts.Capacity = value
		case "storagetype":
			opts.StorageType = value
		}
	}

	if volCap := req.GetVolumeCapability(); volCap != nil {
		if mount := volCap.GetMount(); mount != nil {
			if mount.FsType != "" {
				if opts.FuseType != customFuseFsType && opts.FuseType != mount.FsType {
					return nil, fmt.Errorf("fuseType %q from volumeAttributes conflicts with fsType %q from PV spec", opts.FuseType, mount.FsType)
				}
				opts.FuseType = mount.FsType
			}
			opts.MountOptions = append(opts.MountOptions, mount.MountFlags...)
		}
		switch volCap.GetAccessMode().GetMode() {
		case csi.VolumeCapability_AccessMode_MULTI_NODE_READER_ONLY,
			csi.VolumeCapability_AccessMode_SINGLE_NODE_READER_ONLY:
			opts.ReadOnly = true
		}
	}
	if req.GetReadonly() {
		opts.ReadOnly = true
	}

	if opts.Source == "" && opts.Bucket != "" {
		if opts.Path != "" {
			opts.Source = opts.Bucket + ":" + opts.Path
		} else {
			opts.Source = opts.Bucket
		}
	}

	// Defense in depth: the provider validated these values on the
	// control-plane path, but the per-driver unix socket is reachable from
	// inside the sandbox without passing through the provider. Each value is
	// exported as an environment variable and may be interpolated by the
	// entrypoint, so shell metacharacters are rejected here too.
	for _, field := range []struct{ name, value string }{
		{"source", opts.Source}, {"bucket", opts.Bucket}, {"path", opts.Path},
		{"url", opts.URL}, {"otherOpts", opts.OtherOpts},
		{"capacity", opts.Capacity}, {"storageType", opts.StorageType},
	} {
		if customfusevalidate.HasShellMetachar(field.value) {
			return nil, fmt.Errorf("%s contains invalid shell characters: %q", field.name, customfusevalidate.MaskOptionValues(field.value))
		}
	}

	return opts, nil
}

// precheckAuthConfig validates the auth configuration before mounting.
// Only the default auth type (Secret passthrough) is supported.
func precheckAuthConfig(opts *fuseOptions) error {
	if opts.AuthType != "" {
		return fmt.Errorf("unsupported authType %q; only default (secret passthrough) is currently supported", opts.AuthType)
	}
	return nil
}

// makeMountOptions serializes volume attributes as key=value pairs carried
// through the mount-proxy protocol. mount-proxy maps them to env vars for
// the entrypoint. Source is passed separately via proxyMountRequest.Source.
func (o *fuseOptions) makeMountOptions() []string {
	var opts []string
	if o.Bucket != "" {
		opts = append(opts, "bucket="+o.Bucket)
	}
	if o.URL != "" {
		opts = append(opts, "url="+o.URL)
	}
	if o.Path != "" {
		opts = append(opts, "path="+o.Path)
	}
	if o.OtherOpts != "" {
		opts = append(opts, "otherOpts="+o.OtherOpts)
	}
	if o.Capacity != "" {
		opts = append(opts, "capacity="+o.Capacity)
	}
	if o.StorageType != "" {
		opts = append(opts, "storageType="+o.StorageType)
	}
	opts = append(opts, o.MountOptions...)
	// readOnly is appended last so a conflicting entry in pv.Spec.MountOptions
	// (e.g. "readOnly=false") cannot weaken the read-only semantics derived
	// from the CSI request: mount-proxy builds the entrypoint env from this
	// slice in order, and in a duplicate-key env the last occurrence wins.
	if o.ReadOnly {
		opts = append(opts, "readOnly=true")
	}
	return opts
}

func hasUnitSuffix(s string) bool {
	return len(s) > 0 && !unicode.IsDigit(rune(s[len(s)-1]))
}
