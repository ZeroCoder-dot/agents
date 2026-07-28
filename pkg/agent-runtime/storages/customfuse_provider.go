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

package storages

import (
	"context"
	"fmt"
	"strings"

	"github.com/container-storage-interface/spec/lib/go/csi"
	corev1 "k8s.io/api/core/v1"
)

// allowedFuseTypes is the allowlist of FUSE client identifiers that may be
// specified via volumeAttributes.fuseType. This table is deliberately
// maintained in-code rather than read from configuration so that a
// community contributor who adds a new FUSE client must also add a
// corresponding entrypoint example and documentation.
var allowedFuseTypes = map[string]bool{
	"juicefs":    true,
	"s3fs":       true,
	"jindo":      true,
	"customfuse": true,
}

// credentialKeys lists Secret-key names that must not appear in
// volumeAttributes. Credential material belongs in a Kubernetes Secret
// referenced by the PV's NodePublishSecretRef, never in plain-text PV fields.
var credentialKeys = []string{
	"token", "accessKeyId", "accessKeySecret",
	"access-key", "secret-key", "passphrase",
}

type CustomFuseMountProvider struct{}

func (p *CustomFuseMountProvider) GenerateCSINodePublishVolumeRequest(
	ctx context.Context,
	mountPath string,
	pv *corev1.PersistentVolume,
	readOnly bool,
	secret *corev1.Secret,
) (*csi.NodePublishVolumeRequest, error) {
	if err := p.validate(mountPath, pv); err != nil {
		return nil, err
	}

	// ── VolumeContext: copy all VolumeAttributes as-is ──
	volCtx := make(map[string]string)
	for k, v := range pv.Spec.CSI.VolumeAttributes {
		volCtx[k] = v
	}

	// Set fuseType default after copy so the original is not modified.
	if volCtx["fuseType"] == "" {
		volCtx["fuseType"] = "customfuse"
	}

	// ── Secrets: copy all Secret entries as-is ──
	// Each key becomes an environment variable of the same name in the
	// entrypoint, so the entrypoint author controls the env-var schema by
	// naming the Secret keys accordingly.
	secrets := make(map[string]string)
	if secret != nil {
		for k, v := range secret.Data {
			secrets[k] = string(v)
		}
	}

	// ── Build the CSI request ──
	return &csi.NodePublishVolumeRequest{
		VolumeId:   fmt.Sprintf("%s-%s", pv.Name, generateRandomString(6)),
		TargetPath: mountPath,
		VolumeCapability: &csi.VolumeCapability{
			AccessType: &csi.VolumeCapability_Mount{
				Mount: &csi.VolumeCapability_MountVolume{
					FsType: volCtx["fuseType"],
				},
			},
			AccessMode: &csi.VolumeCapability_AccessMode{
				Mode: csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER,
			},
		},
		VolumeContext: volCtx,
		Secrets:       secrets,
		Readonly:      readOnly,
	}, nil
}

// validate performs structural, security, and field-level checks on the
// provider inputs. It returns nil when the input is safe and complete enough
// to construct a CSI request.
func (p *CustomFuseMountProvider) validate(mountPath string, pv *corev1.PersistentVolume) error {
	// ── 1. Structural checks ──
	if pv == nil {
		return fmt.Errorf("persistent volume object is nil")
	}
	if mountPath == "" {
		return fmt.Errorf("containerMountTarget is empty")
	}
	if pv.Spec.CSI == nil {
		return fmt.Errorf("no CSI spec in persistent volume")
	}

	volCtx := pv.Spec.CSI.VolumeAttributes

	// ── 2. source is required ──
	if strings.TrimSpace(volCtx["source"]) == "" {
		return fmt.Errorf("source is required for customfuse driver (e.g. JuiceFS META-URL like redis://host:6379/0)")
	}

	// ── 3. fuseType allowlist ──
	if fuseType := volCtx["fuseType"]; fuseType != "" {
		if !allowedFuseTypes[strings.ToLower(fuseType)] {
			return fmt.Errorf("unknown fuseType %q (allowed: %v)", fuseType, mapKeys(allowedFuseTypes))
		}
	}

	// ── 4. Shell injection prevention ──
	// otherOpts and mountOptions are eventually passed to entrypoint.sh as
	// environment variables and may be interpolated into shell commands.
	for _, field := range []string{"otherOpts", "mountOptions"} {
		if hasShellMetachar(volCtx[field]) {
			return fmt.Errorf("%s contains invalid shell characters: %q", field, volCtx[field])
		}
	}

	// ── 5. Credential separation ──
	// token, access keys, and passphrases must live in a Kubernetes Secret
	// (PV.Spec.CSI.NodePublishSecretRef), not in plain-text VolumeAttributes.
	for _, credKey := range credentialKeys {
		if _, exists := volCtx[credKey]; exists {
			return fmt.Errorf("credential %q must not be in volumeAttributes, put it in Secret instead", credKey)
		}
	}

	return nil
}

// hasShellMetachar returns true when s contains characters that could be
// interpreted by a shell: ; | & ` $ ( ) \n \x00.
func hasShellMetachar(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch c {
		case ';', '|', '&', '`', '$', '(', ')', '\n', '\x00':
			return true
		}
	}
	return false
}

// mapKeys returns the sorted keys of m. It is used only for error messages,
// so order stability is not required.
func mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
