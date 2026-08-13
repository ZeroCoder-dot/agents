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

// Package customfusevalidate holds the security checks shared between the
// control-plane CustomFuseMountProvider and the sandbox-side CSI node server.
// Both ends must reject the same inputs because mount-proxy exports every
// Secret entry and mount flag as an environment variable of the same name
// into the entrypoint shell: the provider validates the PV+Secret path, and
// the node server repeats the checks for requests that reach it directly
// over the per-driver unix socket without passing through the provider.
package customfusevalidate

import (
	"fmt"
	"regexp"
	"strings"
)

// secretKeyPattern matches Secret keys that can be exported as environment
// variables. The customfuse contract maps every Secret key to an env var of
// the same name consumed by the entrypoint, and bash cannot reference names
// with dashes ($access-key expands as $access plus the literal "-key").
var secretKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// blockedMountOptionKeys are mount options that would become environment
// variables with code-execution or command-redirection side effects once
// mount-proxy exports them to the entrypoint shell: bash sources BASH_ENV at
// startup, glibc loads LD_PRELOAD, PATH redirects command lookup, and
// IFS/PS4/SHELLOPTS alter shell behavior. These keys are rejected outright.
// The match is exact: bash and glibc read only the canonical uppercase names,
// so lowercase variants are harmless and stay allowed.
var blockedMountOptionKeys = map[string]bool{
	"BASH_ENV": true, "ENV": true, "BASHOPTS": true, "SHELLOPTS": true,
	"PROMPT_COMMAND": true, "PS4": true, "IFS": true, "BASH_XTRACEFD": true,
	"LD_PRELOAD": true, "LD_LIBRARY_PATH": true, "LD_AUDIT": true,
	"LD_BIND_NOW": true, "LD_DEBUG": true, "GLIBC_TUNABLES": true,
	"PATH": true, "CDPATH": true, "HISTFILE": true,
}

// reservedSecretKeys are Secret keys that would overwrite the environment
// variables the provider itself injects for the entrypoint: mount-proxy
// exports every Secret entry verbatim and in a duplicate-key env the last
// occurrence wins, so a Secret key like "source" would replace the validated
// mount source, "readOnly" would weaken the read-only semantics derived from
// the CSI request, and "mountpoint" would redirect the mount target.
// Credentials never legitimately share names with these reserved keys.
var reservedSecretKeys = map[string]bool{
	"source": true, "readOnly": true, "mountpoint": true,
	"bucket": true, "url": true, "path": true, "otherOpts": true,
	"capacity": true, "fuseType": true, "authType": true,
}

// optionValuePattern matches key=value pairs in option strings (e.g.
// "cache-size=1024") so that error messages can mask the value part, which
// may carry credential material.
var optionValuePattern = regexp.MustCompile(`([A-Za-z0-9_\-]+=)[^,;\s]*`)

// HasShellMetachar returns true when s contains characters that could be
// interpreted by a shell: ; | & ` $ ( ) \r \n \x00.
func HasShellMetachar(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch c {
		case ';', '|', '&', '`', '$', '(', ')', '\r', '\n', '\x00':
			return true
		}
	}
	return false
}

// MaskOptionValues masks the value of every key=value pair in an option
// string so error messages never echo potential credential material.
func MaskOptionValues(s string) string {
	return optionValuePattern.ReplaceAllString(s, "${1}***")
}

// ValidateSecretData validates every entry of a Secret's Data map: the key
// must be a valid environment variable name, must not be a dangerous
// environment key, must not be a reserved provider key, and the value must
// be single-line. A value containing a newline would inject extra lines into
// the s3fs credential file.
func ValidateSecretData(data map[string][]byte) error {
	for key, value := range data {
		if err := validateSecretEntry(key, string(value)); err != nil {
			return err
		}
	}
	return nil
}

// ValidateSecrets validates every entry of a CSI request's Secrets map, which
// is how the sandbox-side node server receives Secret material.
func ValidateSecrets(secrets map[string]string) error {
	for key, value := range secrets {
		if err := validateSecretEntry(key, value); err != nil {
			return err
		}
	}
	return nil
}

func validateSecretEntry(key, value string) error {
	if !secretKeyPattern.MatchString(key) {
		return fmt.Errorf("secret key %q is not a valid environment variable name", key)
	}
	if blockedMountOptionKeys[key] {
		return fmt.Errorf("secret key %q is not allowed: it would be exported as a dangerous environment variable to the entrypoint", key)
	}
	if reservedSecretKeys[key] {
		return fmt.Errorf("secret key %q is reserved for provider-injected environment variables and must not be overridden", key)
	}
	if strings.ContainsAny(value, "\n\r") {
		return fmt.Errorf("secret %q must not contain a newline", key)
	}
	return nil
}

// IsReservedKey reports whether key is a provider-injected environment name
// that callers must not override through mount options or Secret keys.
func IsReservedKey(key string) bool {
	return reservedSecretKeys[key]
}

// ValidateMountOptions checks every mount option entry (pv.Spec.MountOptions
// on the control plane, VolumeCapability.MountFlags on the node server). Each
// entry becomes one environment variable in the entrypoint, so shell
// metacharacters are rejected and entries whose keys are dangerous
// environment variables or provider-reserved keys are denied outright.
func ValidateMountOptions(opts []string) error {
	for _, opt := range opts {
		if HasShellMetachar(opt) {
			return fmt.Errorf("mount option %q contains invalid shell characters", MaskOptionValues(opt))
		}
		// TrimSpace so " BASH_ENV=x" cannot dodge the exact key match; a
		// whitespace-padded key is never a legitimate mount option.
		key, _, _ := strings.Cut(strings.TrimSpace(opt), "=")
		if blockedMountOptionKeys[key] {
			return fmt.Errorf("mount option %q is not allowed: it would be exported as a dangerous environment variable to the entrypoint", MaskOptionValues(opt))
		}
		if reservedSecretKeys[key] {
			return fmt.Errorf("mount option %q is reserved for provider-injected mount semantics and must not be overridden", MaskOptionValues(opt))
		}
	}
	return nil
}
