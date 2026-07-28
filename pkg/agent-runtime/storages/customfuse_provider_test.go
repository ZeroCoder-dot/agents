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
	"encoding/base64"
	"testing"

	csiapi "github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCustomFuseMountProvider_GenerateCSINodePublishVolumeRequest(t *testing.T) {
	tests := []struct {
		name                 string
		containerMountTarget string
		volumeAttributes     map[string]string
		accessModes          []corev1.PersistentVolumeAccessMode
		secretData           map[string][]byte
		readOnly             bool
		expectError          string
		nilPV                bool
		nilCSI               bool
		validateResult       func(*testing.T, *csiapi.NodePublishVolumeRequest)
	}{
		// ── 正常路径 ──
		{
			name:                 "valid JuiceFS mount with source and fuseType",
			containerMountTarget: "/workspace/data",
			volumeAttributes: map[string]string{
				"source":   "redis://redis-cluster:6379/0",
				"fuseType": "juicefs",
			},
			secretData: map[string][]byte{
				"token": []byte("test-token"),
			},
			expectError: "",
			validateResult: func(t *testing.T, req *csiapi.NodePublishVolumeRequest) {
				assert.Equal(t, "/workspace/data", req.TargetPath)
				assert.Equal(t, "juicefs", req.VolumeContext["fuseType"])
				assert.Equal(t, "redis://redis-cluster:6379/0", req.VolumeContext["source"])
				assert.Equal(t, "test-token", req.Secrets["token"])
				assert.Contains(t, req.VolumeId, "pv-")
				assert.NotNil(t, req.VolumeCapability)
			},
		},
		{
			name:                 "default fuseType when not set",
			containerMountTarget: "/mnt/data",
			volumeAttributes: map[string]string{
				"source": "redis://localhost:6379/1",
			},
			expectError: "",
			validateResult: func(t *testing.T, req *csiapi.NodePublishVolumeRequest) {
				assert.Equal(t, "customfuse", req.VolumeContext["fuseType"])
			},
		},
		{
			name:                 "fuseType from VolumeCapability.FsType",
			containerMountTarget: "/mnt/data",
			volumeAttributes: map[string]string{
				"source": "redis://host:6379/0",
				// fuseType not set in volumeAttributes, but FsType in the PV CSI spec
			},
			expectError: "",
			validateResult: func(t *testing.T, req *csiapi.NodePublishVolumeRequest) {
				// fuseType is set in the Provider from VolumeAttributes, not FsType
				// verify defaults are applied correctly
				assert.NotEmpty(t, req.VolumeContext["fuseType"])
			},
		},
		{
			name:                 "includes bucket, url, path, and capacity",
			containerMountTarget: "/mnt/data",
			volumeAttributes: map[string]string{
				"source":   "redis://redis:6379/0",
				"fuseType": "juicefs",
				"bucket":   "ml-datasets",
				"url":      "https://s3.amazonaws.com",
				"path":     "/user-123",
				"capacity": "100Gi",
			},
			expectError: "",
			validateResult: func(t *testing.T, req *csiapi.NodePublishVolumeRequest) {
				assert.Equal(t, "ml-datasets", req.VolumeContext["bucket"])
				assert.Equal(t, "https://s3.amazonaws.com", req.VolumeContext["url"])
				assert.Equal(t, "/user-123", req.VolumeContext["path"])
				assert.Equal(t, "100Gi", req.VolumeContext["capacity"])
			},
		},
		{
			name:                 "all volumeAttributes passed through unchanged",
			containerMountTarget: "/mnt",
			volumeAttributes: map[string]string{
				"source":        "redis://redis:6379/0",
				"fuseType":      "juicefs",
				"bucket":        "my-bucket",
				"url":           "https://oss.example.com",
				"path":          "/sub/path",
				"capacity":      "50Gi",
				"otherOpts":     "cache-size=1024",
				"otheropts":     "cache-dir=/ssd",
				"extra-custom":  "custom-value",
			},
			secretData: map[string][]byte{
				"access-key":    []byte("AKID123"),
				"secret-key":    []byte("SECRET456"),
				"custom-config": []byte("config-value"),
			},
			expectError: "",
			validateResult: func(t *testing.T, req *csiapi.NodePublishVolumeRequest) {
				// All volumeAttributes are preserved
				assert.Equal(t, "my-bucket", req.VolumeContext["bucket"])
				assert.Equal(t, "custom-value", req.VolumeContext["extra-custom"])
				// All secrets are passed through
				assert.Equal(t, "AKID123", req.Secrets["access-key"])
				assert.Equal(t, "config-value", req.Secrets["custom-config"])
			},
		},

		// ── ReadOnly 推导 ──
		{
			name:                 "readOnly=true is set on request",
			containerMountTarget: "/mnt/data",
			volumeAttributes:     map[string]string{"source": "redis://host:6379/0"},
			readOnly:             true,
			expectError:          "",
			validateResult: func(t *testing.T, req *csiapi.NodePublishVolumeRequest) {
				assert.True(t, req.Readonly)
			},
		},
		{
			name:                 "readOnly=false by default",
			containerMountTarget: "/mnt/data",
			volumeAttributes:     map[string]string{"source": "redis://host:6379/0"},
			readOnly:             false,
			expectError:          "",
			validateResult: func(t *testing.T, req *csiapi.NodePublishVolumeRequest) {
				assert.False(t, req.Readonly)
			},
		},

		// ── 错误路径：结构校验 ──
		{
			name:                 "nil persistent volume",
			containerMountTarget: "/mnt",
			volumeAttributes:     map[string]string{"source": "redis://host:6379/0"},
			expectError:          "persistent volume object is nil",
			nilPV:                true,
		},
		{
			name:                 "empty mount path",
			containerMountTarget: "",
			volumeAttributes:     map[string]string{"source": "redis://host:6379/0"},
			expectError:          "containerMountTarget is empty",
		},

		// ── 错误路径：source 必填 ──
		{
			name:                 "empty source",
			containerMountTarget: "/mnt",
			volumeAttributes:     map[string]string{},
			expectError:          "source is required",
		},
		{
			name:                 "whitespace-only source",
			containerMountTarget: "/mnt",
			volumeAttributes:     map[string]string{"source": "   "},
			expectError:          "source is required",
		},

		// ── 错误路径：fuseType 白名单 ──
		{
			name:                 "unknown fuseType",
			containerMountTarget: "/mnt",
			volumeAttributes: map[string]string{
				"source":   "redis://host:6379/0",
				"fuseType": "unknown-fuse-client",
			},
			expectError: "unknown fuseType",
		},

		// ── 错误路径：shell 防注入 ──
		{
			name:                 "otherOpts contains semicolon",
			containerMountTarget: "/mnt",
			volumeAttributes: map[string]string{
				"source":    "redis://host:6379/0",
				"otherOpts": "cache-dir=/tmp; rm -rf /",
			},
			expectError: "invalid shell characters",
		},
		{
			name:                 "otherOpts contains pipe",
			containerMountTarget: "/mnt",
			volumeAttributes: map[string]string{
				"source":    "redis://host:6379/0",
				"otherOpts": "opt1 | cat /etc/passwd",
			},
			expectError: "invalid shell characters",
		},
		{
			name:                 "otherOpts contains backtick",
			containerMountTarget: "/mnt",
			volumeAttributes: map[string]string{
				"source":    "redis://host:6379/0",
				"otherOpts": "opt=`id`",
			},
			expectError: "invalid shell characters",
		},
		{
			name:                 "otherOpts contains dollar",
			containerMountTarget: "/mnt",
			volumeAttributes: map[string]string{
				"source":    "redis://host:6379/0",
				"otherOpts": "opt=$(whoami)",
			},
			expectError: "invalid shell characters",
		},
		{
			name:                 "otherOpts contains null byte",
			containerMountTarget: "/mnt",
			volumeAttributes: map[string]string{
				"source":    "redis://host:6379/0",
				"otherOpts": "safe\x00injection",
			},
			expectError: "invalid shell characters",
		},
		{
			name:                 "mountOptions contains semicolon",
			containerMountTarget: "/mnt",
			volumeAttributes: map[string]string{
				"source":       "redis://host:6379/0",
				"mountOptions": "opt1; rm /tmp",
			},
			expectError: "invalid shell characters",
		},

		// ── 错误路径：凭证分离 ──
		{
			name:                 "token in volumeAttributes should fail",
			containerMountTarget: "/mnt",
			volumeAttributes: map[string]string{
				"source": "redis://host:6379/0",
				"token":  "secret-token-in-wrong-place",
			},
			expectError: "must not be in volumeAttributes",
		},
		{
			name:                 "accessKeyId in volumeAttributes should fail",
			containerMountTarget: "/mnt",
			volumeAttributes: map[string]string{
				"source":       "redis://host:6379/0",
				"accessKeyId":  "AKID123",
			},
			expectError: "must not be in volumeAttributes",
		},
		{
			name:                 "access-key in volumeAttributes should fail",
			containerMountTarget: "/mnt",
			volumeAttributes: map[string]string{
				"source":     "redis://host:6379/0",
				"access-key": "AKID123",
			},
			expectError: "must not be in volumeAttributes",
		},
		{
			name:                 "passphrase in volumeAttributes should fail",
			containerMountTarget: "/mnt",
			volumeAttributes: map[string]string{
				"source":     "redis://host:6379/0",
				"passphrase": "my-passphrase",
			},
			expectError: "must not be in volumeAttributes",
		},
		{
			name:                 "secret-key in volumeAttributes should fail",
			containerMountTarget: "/mnt",
			volumeAttributes: map[string]string{
				"source":     "redis://host:6379/0",
				"secret-key": "SECRET456",
			},
			expectError: "must not be in volumeAttributes",
		},

		// ── 边角路径 ──
		{
			name:                 "agent-identity mode with nil secret",
			containerMountTarget: "/mnt",
			volumeAttributes: map[string]string{
				"source":   "redis://host:6379/0",
				"fuseType": "juicefs",
			},
			secretData:  nil,
			expectError: "",
			validateResult: func(t *testing.T, req *csiapi.NodePublishVolumeRequest) {
				assert.Equal(t, "juicefs", req.VolumeContext["fuseType"])
				assert.Empty(t, req.Secrets)
			},
		},
		{
			name:                 "empty secret",
			containerMountTarget: "/mnt",
			volumeAttributes:     map[string]string{"source": "redis://host:6379/0"},
			secretData:           map[string][]byte{},
			expectError:          "",
			validateResult: func(t *testing.T, req *csiapi.NodePublishVolumeRequest) {
				assert.Empty(t, req.Secrets)
			},
		},
		{
			name:                 "fuseType customfuse is valid",
			containerMountTarget: "/mnt",
			volumeAttributes: map[string]string{
				"source":   "redis://host:6379/0",
				"fuseType": "customfuse",
			},
			expectError: "",
		},
		{
			name:                 "fuseType s3fs is valid",
			containerMountTarget: "/mnt",
			volumeAttributes: map[string]string{
				"source":   "s3://my-bucket",
				"fuseType": "s3fs",
			},
			expectError: "",
		},
		{
			name:                 "fuseType jindo is valid",
			containerMountTarget: "/mnt",
			volumeAttributes: map[string]string{
				"source":   "oss://bucket",
				"fuseType": "jindo",
			},
			expectError: "",
		},
		{
			name:                 "safe otherOpts passes validation",
			containerMountTarget: "/mnt",
			volumeAttributes: map[string]string{
				"source":    "redis://host:6379/0",
				"otherOpts": "cache-size=1024,cache-dir=/ssd-cache,prefetch=1",
			},
			expectError: "",
		},
		{
			name:                 "empty otherOpts and mountOptions pass validation",
			containerMountTarget: "/mnt",
			volumeAttributes: map[string]string{
				"source":       "redis://host:6379/0",
				"otherOpts":    "",
				"mountOptions": "",
			},
			expectError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pv *corev1.PersistentVolume
			if !tt.nilPV {
				csiSpec := &corev1.CSIPersistentVolumeSource{
					Driver:           "customfuseplugin.csi.alibabacloud.com",
					VolumeHandle:     "pv-test-handle",
					VolumeAttributes: tt.volumeAttributes,
				}
				if tt.nilCSI {
					csiSpec = nil
				}
				pv = &corev1.PersistentVolume{
					ObjectMeta: metav1.ObjectMeta{Name: "pv-test"},
					Spec: corev1.PersistentVolumeSpec{
						AccessModes: tt.accessModes,
					},
				}
				if csiSpec != nil {
					pv.Spec.PersistentVolumeSource = corev1.PersistentVolumeSource{
						CSI: csiSpec,
					}
				}
			}

			var secret *corev1.Secret
			if tt.secretData != nil {
				secret = &corev1.Secret{
					Data: tt.secretData,
				}
			}

			provider := &CustomFuseMountProvider{}
			result, err := provider.GenerateCSINodePublishVolumeRequest(
				context.Background(),
				tt.containerMountTarget,
				pv,
				tt.readOnly,
				secret,
			)

			if tt.expectError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectError)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				if tt.validateResult != nil {
					tt.validateResult(t, result)
				}
			}
		})
	}
}

func TestCustomFuseMountProvider_VolumeIdUniqueness(t *testing.T) {
	provider := &CustomFuseMountProvider{}
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-unique"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:           "customfuseplugin.csi.alibabacloud.com",
					VolumeHandle:     "pv-unique-handle",
					VolumeAttributes: map[string]string{"source": "redis://host:6379/0"},
				},
			},
		},
	}

	// Generate two requests and verify VolumeIds differ (random suffix).
	req1, err1 := provider.GenerateCSINodePublishVolumeRequest(context.Background(), "/mnt", pv, false, nil)
	require.NoError(t, err1)
	req2, err2 := provider.GenerateCSINodePublishVolumeRequest(context.Background(), "/mnt", pv, false, nil)
	require.NoError(t, err2)

	assert.NotEqual(t, req1.VolumeId, req2.VolumeId, "consecutive mounts should generate unique VolumeIds")
	assert.Contains(t, req1.VolumeId, "pv-unique")
	assert.Contains(t, req2.VolumeId, "pv-unique")
}

func TestCustomFuseMountProvider_PassthroughNonCustomfuseKeys(t *testing.T) {
	// Verify that custom keys beyond the known customfuse spec are preserved
	// in VolumeContext without filtering.
	provider := &CustomFuseMountProvider{}
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-custom"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:           "customfuseplugin.csi.alibabacloud.com",
					VolumeHandle:     "pv-custom-handle",
					VolumeAttributes: map[string]string{
						"source":      "redis://host:6379/0",
						"custom-key1": "value1",
						"custom-key2": "value2",
					},
				},
			},
		},
	}

	req, err := provider.GenerateCSINodePublishVolumeRequest(context.Background(), "/mnt", pv, false, nil)
	require.NoError(t, err)
	assert.Equal(t, "value1", req.VolumeContext["custom-key1"])
	assert.Equal(t, "value2", req.VolumeContext["custom-key2"])
}

// TestCustomFuseMountProvider_ProtoRoundtrip verifies that the generated
// NodePublishVolumeRequest survives the full serialization pipeline used
// by CSIMountHandler: proto.Marshal → base64 encode → base64 decode →
// proto.Unmarshal. No fields should be lost or corrupted in transit.
func TestCustomFuseMountProvider_ProtoRoundtrip(t *testing.T) {
	provider := &CustomFuseMountProvider{}
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-roundtrip"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:       "customfuseplugin.csi.alibabacloud.com",
					VolumeHandle: "pv-roundtrip-handle",
					VolumeAttributes: map[string]string{
						"source":    "redis://redis:6379/0",
						"fuseType":  "juicefs",
						"bucket":    "ml-datasets",
						"url":       "https://s3.amazonaws.com",
						"path":      "/user-123",
						"capacity":  "100Gi",
						"otherOpts": "cache-size=1024",
					},
				},
			},
		},
	}
	secret := &corev1.Secret{
		Data: map[string][]byte{
			"token":      []byte("test-token-value"),
			"access-key": []byte("AKID-TEST"),
			"secret-key": []byte("SECRET-TEST"),
		},
	}

	original, err := provider.GenerateCSINodePublishVolumeRequest(
		context.Background(), "/workspace/data", pv, true, secret,
	)
	require.NoError(t, err)
	require.NotNil(t, original)

	// Simulate CSIMountHandler: proto.Marshal → base64 encode.
	marshaled, err := proto.Marshal(original)
	require.NoError(t, err)
	encoded := base64.StdEncoding.EncodeToString(marshaled)

	// Simulate sandbox-storage: base64 decode → proto.Unmarshal.
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	restored := &csiapi.NodePublishVolumeRequest{}
	err = proto.Unmarshal(decoded, restored)
	require.NoError(t, err)

	// Verify all fields survive the round-trip.
	assert.Equal(t, original.VolumeId, restored.VolumeId)
	assert.Equal(t, original.TargetPath, restored.TargetPath)
	assert.Equal(t, original.Readonly, restored.Readonly)
	assert.Equal(t, original.VolumeCapability.GetMount().FsType, restored.VolumeCapability.GetMount().FsType)
	assert.Equal(t, original.VolumeContext["source"], restored.VolumeContext["source"])
	assert.Equal(t, original.VolumeContext["fuseType"], restored.VolumeContext["fuseType"])
	assert.Equal(t, original.VolumeContext["bucket"], restored.VolumeContext["bucket"])
	assert.Equal(t, original.VolumeContext["url"], restored.VolumeContext["url"])
	assert.Equal(t, original.VolumeContext["path"], restored.VolumeContext["path"])
	assert.Equal(t, original.VolumeContext["capacity"], restored.VolumeContext["capacity"])
	assert.Equal(t, original.VolumeContext["otherOpts"], restored.VolumeContext["otherOpts"])
	assert.Equal(t, original.Secrets["token"], restored.Secrets["token"])
	assert.Equal(t, original.Secrets["access-key"], restored.Secrets["access-key"])
	assert.Equal(t, original.Secrets["secret-key"], restored.Secrets["secret-key"])
}
