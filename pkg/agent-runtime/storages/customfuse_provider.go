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
	"maps"
	"regexp"
	"sort"
	"strings"

	"github.com/container-storage-interface/spec/lib/go/csi"
	corev1 "k8s.io/api/core/v1"

	"github.com/openkruise/agents/pkg/agent-runtime/customfusevalidate"
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
	"token", "accessKeyId", "accessKeySecret", "passphrase", "password", "passwd",
	"access-key", "secret-key", "access_key", "secret_key", "ak", "sk", "secret",
}

// safeForwardPattern matches values made only of characters that are safe to
// interpolate into a shell command: metadata URLs (redis://host:6379/0,
// s3://bucket) and plain identifiers. It is shared by every volumeAttributes
// field that is forwarded to the sidecar entrypoint as an environment
// variable — source, url, bucket and path. Those fields are validated with
// this allowlist rather than a denylist because the entrypoint may
// interpolate them into a mount command, and every future entrypoint must
// stay safe even when it forgets to quote.
var safeForwardPattern = regexp.MustCompile(`^[A-Za-z0-9_\-:/@.%]+$`)

// mountPathPattern matches absolute, shell-safe container mount targets.
var mountPathPattern = regexp.MustCompile(`^/[A-Za-z0-9_\-./]+$`)

// credInURLPattern matches userinfo (user:pass) embedded in a URL. It masks
// up to the last '@' before the path or whitespace so that URLs containing
// multiple '@' segments never leak credentials into error messages.
var credInURLPattern = regexp.MustCompile(`://[^/\s]*@`)

// credUserInfoPattern matches userinfo without a scheme (user:pass@host),
// which safeForwardPattern allows through but a scheme-bearing pattern would
// miss in error output: the value is rejected by the charset check only when
// it also carries an invalid character, and the error message must not echo
// the credential part.
var credUserInfoPattern = regexp.MustCompile(`([^/\s:@]+:)[^/@\s]*@`)

// queryValuePattern matches name=value pairs in URL query strings and
// fragments (e.g. ?token=xxx or ?X-Amz-Signature=yyy) so their values can be
// masked in error messages. Query URLs never pass the source allowlist, but
// they must not leak credentials into logs when rejected.
var queryValuePattern = regexp.MustCompile(`([?&#][^=&\s]*=)[^&\s#]*`)

// CustomFuseMountProvider generates CSI NodePublishVolume requests for the
// generic FUSE driver (customfuseplugin.csi.alibabacloud.com). It validates
// inputs for shell safety and credential hygiene, then forwards the PV's
// volume attributes and the referenced Secret verbatim to the FUSE
// entrypoint inside the sandbox csi-sidecar container.
type CustomFuseMountProvider struct{}

// GenerateCSINodePublishVolumeRequest validates the PV, Secret and mount
// target, then builds a NodePublishVolumeRequest whose VolumeContext and
// Secrets pass through unchanged to the FUSE entrypoint. The returned
// request is never partially built alongside an error: callers can rely on
// (nil, err) when validation fails.
func (p *CustomFuseMountProvider) GenerateCSINodePublishVolumeRequest(
	ctx context.Context,
	containerMountTarget string,
	pv *corev1.PersistentVolume,
	readOnly bool,
	secret *corev1.Secret,
) (*csi.NodePublishVolumeRequest, error) {
	if err := p.validate(containerMountTarget, pv, secret); err != nil {
		return nil, err
	}

	// VolumeContext: copy all VolumeAttributes as-is
	// validate() guarantees VolumeAttributes is non-nil (source is required),
	// so the fuseType default below cannot assign to a nil map. The explicit
	// nil check keeps that guarantee from becoming a panic if the validate
	// call order ever changes.
	volCtx := maps.Clone(pv.Spec.CSI.VolumeAttributes)
	if volCtx == nil {
		return nil, fmt.Errorf("volumeAttributes must not be nil")
	}

	// Set fuseType default after copy so the original is not modified.
	// validate() accepts case-insensitive input; normalize to lowercase here
	// so the entrypoint always receives the canonical identifier. All case
	// variants of the key are collapsed into the canonical lowercase key so
	// parseOptions, which extracts keys case-insensitively, sees exactly one
	// value and the FsType/VolumeContext cross-check can never fire on
	// provider-generated requests.
	fuseType := "customfuse"
	for k, v := range volCtx {
		if strings.EqualFold(k, "fuseType") {
			if strings.TrimSpace(v) != "" {
				fuseType = strings.ToLower(v)
			}
			delete(volCtx, k)
		}
	}
	volCtx["fuseType"] = fuseType

	// Secrets: copy all Secret entries as-is
	// Each key becomes an environment variable of the same name in the
	// entrypoint, so the entrypoint author controls the env-var schema by
	// naming the Secret keys accordingly.
	secrets := make(map[string]string)
	if secret != nil {
		for k, v := range secret.Data {
			secrets[k] = string(v)
		}
	}

	// Read-only must be derived from both the requested mount and the PV
	// access modes; do not weaken either source.
	isReadOnly := IsPureReadOnly(pv.Spec.AccessModes) || readOnly

	// A read-only mount is advertised as READER_ONLY so the CSI plugin and
	// the entrypoint can rely on the AccessMode semantics.
	accessMode := csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER
	if isReadOnly {
		accessMode = csi.VolumeCapability_AccessMode_SINGLE_NODE_READER_ONLY
	}

	// VolumeId must be stable per volume because the CSI node plugin keys
	// mount state by it. Prefer the storage-system handle and fall back to
	// the PV name for statically provisioned volumes.
	volumeID := pv.Name
	if pv.Spec.CSI.VolumeHandle != "" {
		volumeID = pv.Spec.CSI.VolumeHandle
	}

	// Build the CSI request
	return &csi.NodePublishVolumeRequest{
		VolumeId:   volumeID,
		TargetPath: containerMountTarget,
		VolumeCapability: &csi.VolumeCapability{
			AccessType: &csi.VolumeCapability_Mount{
				Mount: &csi.VolumeCapability_MountVolume{
					FsType:     volCtx["fuseType"],
					MountFlags: pv.Spec.MountOptions,
				},
			},
			AccessMode: &csi.VolumeCapability_AccessMode{
				Mode: accessMode,
			},
		},
		VolumeContext: volCtx,
		Secrets:       secrets,
		Readonly:      isReadOnly,
	}, nil
}

// validate performs structural, security, and field-level checks on the
// provider inputs. It returns nil when the input is safe and complete enough
// to construct a CSI request.
func (p *CustomFuseMountProvider) validate(containerMountTarget string, pv *corev1.PersistentVolume, secret *corev1.Secret) error {
	if err := validateVolume(containerMountTarget, pv); err != nil {
		return err
	}
	volCtx := pv.Spec.CSI.VolumeAttributes
	if err := validateForwardedFields(volCtx); err != nil {
		return err
	}
	if err := validateMountTarget(containerMountTarget); err != nil {
		return err
	}
	if err := validateFuseType(volCtx); err != nil {
		return err
	}
	if err := validateShellSafeFields(volCtx, pv.Spec.MountOptions); err != nil {
		return err
	}
	if err := validateCredentialSeparation(volCtx); err != nil {
		return err
	}
	return validateSecret(secret)
}

// validateVolume checks the structural preconditions: a non-nil PV with a
// CSI spec and a non-empty mount target.
func validateVolume(containerMountTarget string, pv *corev1.PersistentVolume) error {
	if pv == nil {
		return fmt.Errorf("persistent volume object is nil")
	}
	if strings.TrimSpace(containerMountTarget) == "" {
		return fmt.Errorf("containerMountTarget is empty")
	}
	if pv.Spec.CSI == nil {
		return fmt.Errorf("no CSI spec in persistent volume")
	}
	return nil
}

// forEachAttr applies fn to the value of every volCtx key whose
// case-insensitive form matches attr. parseOptions extracts keys from the
// VolumeContext case-insensitively, so a key like "CAPACITY" would otherwise
// bypass every check here; every variant must be validated and any invalid
// value rejects the request.
func forEachAttr(volCtx map[string]string, attr string, fn func(value string) error) error {
	for k, v := range volCtx {
		if strings.EqualFold(k, attr) {
			if err := fn(v); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateForwardedFields checks every volumeAttributes field that is
// forwarded to the sidecar entrypoint as an environment variable.
//
// source is required and shell-safe: it may be interpolated into a mount
// command, so it must match a strict character set rather than a denylist.
// The charset check runs on the raw value because the raw value is what gets
// forwarded; the error message masks credentials embedded in the URL so they
// never reach logs.
//
// url, bucket, path and storageType are optional and must match the same
// safe character set. Whitespace-only values count as unset. url may embed
// credentials (http://user:pass@host), so its error output is masked.
func validateForwardedFields(volCtx map[string]string) error {
	// Every case variant of source is checked because parseOptions extracts
	// keys case-insensitively; whitespace-only variants count as unset and
	// an all-unset source set is missing.
	sourceSet := false
	if err := forEachAttr(volCtx, "source", func(value string) error {
		if strings.TrimSpace(value) == "" {
			return nil
		}
		sourceSet = true
		if !safeForwardPattern.MatchString(value) {
			return fmt.Errorf("source %q contains invalid characters", maskURLCreds(value))
		}
		return nil
	}); err != nil {
		return err
	}
	if !sourceSet {
		return fmt.Errorf("source is required for customfuse driver (e.g. JuiceFS META-URL like redis://host:6379/0)")
	}

	// url, bucket, path and storageType are optional: whitespace-only values
	// count as unset. When present they must match the same safe character set
	// as source; url may embed credentials (http://user:pass@host), so its
	// error output is masked.
	for _, field := range []string{"url", "bucket", "path", "storageType"} {
		if err := forEachAttr(volCtx, field, func(value string) error {
			if strings.TrimSpace(value) == "" {
				return nil
			}
			if !safeForwardPattern.MatchString(value) {
				return fmt.Errorf("%s %q contains invalid characters", field, maskURLCreds(value))
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// validateMountTarget checks that the container mount target is an absolute
// path made only of safe characters, and that it does not traverse to the
// parent directory. Traversal would let a malicious volume escape the
// mount-root subtree and shadow host paths.
func validateMountTarget(containerMountTarget string) error {
	if !strings.HasPrefix(containerMountTarget, "/") {
		return fmt.Errorf("containerMountTarget %q must be absolute", containerMountTarget)
	}
	if !mountPathPattern.MatchString(containerMountTarget) {
		return fmt.Errorf("containerMountTarget %q must contain only safe characters", containerMountTarget)
	}
	for _, seg := range strings.Split(containerMountTarget, "/") {
		if seg == ".." {
			return fmt.Errorf("containerMountTarget %q must not traverse to the parent directory", containerMountTarget)
		}
	}
	return nil
}

// validateFuseType restricts volumeAttributes.fuseType to the allowlist.
// Empty means "customfuse" (the provider default), set by the caller after
// validation. The match is case-insensitive; the canonical lowercase value
// is what reaches the entrypoint.
func validateFuseType(volCtx map[string]string) error {
	// Case variants of the key are checked because parseOptions extracts
	// keys case-insensitively.
	return forEachAttr(volCtx, "fuseType", func(value string) error {
		if value != "" && !allowedFuseTypes[strings.ToLower(value)] {
			return fmt.Errorf("unknown fuseType %q (allowed: %v)", value, mapKeys(allowedFuseTypes))
		}
		return nil
	})
}

// validateShellSafeFields checks every option string that mount-proxy will
// export as an environment variable and that the entrypoint may interpolate
// into a mount command: the otherOpts/mountOptions/capacity volumeAttributes
// fields, and pv.Spec.MountOptions (each entry becomes one env var). Shell
// metacharacters are rejected, and mountOptions entries whose keys are
// environment variables with code-execution or command-redirection side
// effects are denied outright.
func validateShellSafeFields(volCtx map[string]string, mountOptions []string) error {
	// Case variants of the keys are checked because parseOptions extracts
	// keys case-insensitively.
	for _, field := range []string{"otherOpts", "mountOptions", "capacity"} {
		if err := forEachAttr(volCtx, field, func(value string) error {
			if customfusevalidate.HasShellMetachar(value) {
				return fmt.Errorf("%s contains invalid shell characters: %q", field, customfusevalidate.MaskOptionValues(value))
			}
			// otherOpts/mountOptions are option lists ("key=value,...") that
			// the entrypoint appends to the -o string after the
			// provider-composed options, so a reserved key inside them would
			// override provider-injected mount semantics just like a
			// pv.Spec.MountOptions entry. capacity is a plain value and has no
			// option list.
			if field != "capacity" {
				for _, opt := range strings.Split(value, ",") {
					if key, _, _ := strings.Cut(strings.TrimSpace(opt), "="); customfusevalidate.IsReservedKey(key) {
						return fmt.Errorf("%s option %q is reserved for provider-injected mount semantics and must not be overridden", field, customfusevalidate.MaskOptionValues(opt))
					}
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return customfusevalidate.ValidateMountOptions(mountOptions)
}

// validateCredentialSeparation forces token, access keys, and passphrases to
// live in a Kubernetes Secret (PV.Spec.CSI.NodePublishSecretRef) instead of
// plain-text VolumeAttributes.
func validateCredentialSeparation(volCtx map[string]string) error {
	// Keys are matched case-insensitively, mirroring parseOptions.
	for _, credKey := range credentialKeys {
		if err := forEachAttr(volCtx, credKey, func(value string) error {
			return fmt.Errorf("credential %q must not be in volumeAttributes, put it in Secret instead", credKey)
		}); err != nil {
			return err
		}
	}
	return nil
}

// validateSecret checks that every Secret key is a valid environment variable
// name, is not a dangerous environment key, is not a reserved provider key,
// and that every value is single-line. The customfuse contract maps each
// Secret key to an environment variable of the same name in the entrypoint:
// bash cannot reference names with dashes or leading digits, a key like
// BASH_ENV would be sourced by the entrypoint shell at startup (arbitrary
// code execution), a reserved key would override provider-injected mount
// semantics, and a value containing a newline would inject extra lines into
// the s3fs credential file.
func validateSecret(secret *corev1.Secret) error {
	if secret == nil {
		return nil
	}
	return customfusevalidate.ValidateSecretData(secret.Data)
}

// maskURLCreds replaces credentials embedded in URLs with *** so that error
// messages never leak them into logs. It masks userinfo and query/fragment
// values, where credentials canonically live. URL path segments are not
// masked: paths can legitimately carry bucket/object keys and masking them
// would corrupt the diagnostic value of the error message.
func maskURLCreds(s string) string {
	s = credInURLPattern.ReplaceAllString(s, "://***@")
	s = credUserInfoPattern.ReplaceAllString(s, "${1}***@")
	return queryValuePattern.ReplaceAllString(s, "${1}***")
}

// mapKeys returns the sorted keys of m. It is used only for error messages;
// sorting keeps the allowed list stable across calls and test runs.
func mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
