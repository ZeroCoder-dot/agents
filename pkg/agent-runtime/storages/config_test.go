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
	"os"
	"strings"
	"testing"

	"github.com/openkruise/agents/pkg/agent-runtime/common"
)

// TestInitFunction tests the package initialization logic with environment variable
func TestInitFunction(t *testing.T) {
	// Save original environment variable value
	originalEnvValue := os.Getenv(common.ENV_DYNAMIC_STORAGE_DRIVER_LIST)
	defer func() {
		// Restore original environment variable after test
		if originalEnvValue == "" {
			os.Unsetenv(common.ENV_DYNAMIC_STORAGE_DRIVER_LIST)
		} else {
			os.Setenv(common.ENV_DYNAMIC_STORAGE_DRIVER_LIST, originalEnvValue)
		}
	}()

	// Reset global state before test
	resetInitializeProviderFuncs()

	// Set up test environment variable
	testDriverList := "driver1,driver2,driver3"
	os.Setenv(common.ENV_DYNAMIC_STORAGE_DRIVER_LIST, testDriverList)

	// Manually execute initialization logic to simulate init function behavior
	// Note: We can't directly test init() as it runs only once during package loading
	// So we manually implement the same logic with closure fix
	dynamicDriverList := strings.Split(testDriverList, ",")
	var tempInitializeProviderFuncs []initProviderFunc

	for _, driverName := range dynamicDriverList {
		driverName := driverName                 // Capture loop variable to avoid closure trap
		if strings.TrimSpace(driverName) != "" { // Skip empty entries
			tempInitializeProviderFuncs = append(tempInitializeProviderFuncs,
				func(sp *StorageProvider) {
					sp.RegisterProvider(driverName, &MountProvider{})
				})
		}
	}

	// Verify that initialization logic would create correct number of provider functions
	expectedCount := 3 // Number of non-empty drivers in our test case
	actualCount := len(tempInitializeProviderFuncs)

	if actualCount != expectedCount {
		t.Errorf("Expected %d provider functions, got %d", expectedCount, actualCount)
	}

	// Test with empty environment variable
	resetInitializeProviderFuncs()
	os.Setenv(common.ENV_DYNAMIC_STORAGE_DRIVER_LIST, "")

	emptyDriverList := strings.Split("", ",")
	var emptyTempFuncs []initProviderFunc
	for _, driverName := range emptyDriverList {
		driverName := driverName
		if strings.TrimSpace(driverName) != "" {
			emptyTempFuncs = append(emptyTempFuncs,
				func(sp *StorageProvider) {
					sp.RegisterProvider(driverName, &MountProvider{})
				})
		}
	}

	// Should have 1 element because Split("") returns [""]
	if len(emptyTempFuncs) != 0 { // After trimming empty string
		t.Errorf("Expected 0 provider functions for empty env var, got %d", len(emptyTempFuncs))
	}
}

func TestCustomFuseRegistration(t *testing.T) {
	originalEnvValue := os.Getenv(common.ENV_DYNAMIC_STORAGE_DRIVER_LIST)
	defer func() {
		if originalEnvValue == "" {
			os.Unsetenv(common.ENV_DYNAMIC_STORAGE_DRIVER_LIST)
		} else {
			os.Setenv(common.ENV_DYNAMIC_STORAGE_DRIVER_LIST, originalEnvValue)
		}
	}()
	resetInitializeProviderFuncs()

	// Simulate the init() logic as done in TestInitFunction
	testDriverList := "nasplugin.csi.alibabacloud.com,customfuseplugin.csi.alibabacloud.com,ossplugin.csi.alibabacloud.com"
	os.Setenv(common.ENV_DYNAMIC_STORAGE_DRIVER_LIST, testDriverList)

	dynamicDriverList := strings.Split(testDriverList, ",")
	var tempFuncs []initProviderFunc
	for _, driverName := range dynamicDriverList {
		drv := driverName
		if strings.TrimSpace(drv) == "" {
			continue
		}
		switch {
		case drv == "customfuseplugin.csi.alibabacloud.com" || strings.Contains(drv, "customfuse"):
			tempFuncs = append(tempFuncs,
				func(sp *StorageProvider) {
					sp.RegisterProvider(drv, &CustomFuseMountProvider{})
				})
		default:
			tempFuncs = append(tempFuncs,
				func(sp *StorageProvider) {
					sp.RegisterProvider(drv, &MountProvider{})
				})
		}
	}

	if len(tempFuncs) != 3 {
		t.Fatalf("expected 3 providers, got %d", len(tempFuncs))
	}

	// Verify the registered types by calling each function against a fresh registry.
	sp := NewStorageProvider()
	for _, fn := range tempFuncs {
		fn(sp.(*StorageProvider))
	}

	// customfuse driver → CustomFuseMountProvider
	customfuseDrv := "customfuseplugin.csi.alibabacloud.com"
	customProvider, exists := sp.GetProvider(customfuseDrv)
	if !exists {
		t.Fatalf("customfuse driver %q not registered", customfuseDrv)
	}
	if _, ok := customProvider.(*CustomFuseMountProvider); !ok {
		t.Errorf("customfuse driver %q expected *CustomFuseMountProvider, got %T", customfuseDrv, customProvider)
	}

	// non-customfuse drivers → MountProvider
	nasProvider, exists := sp.GetProvider("nasplugin.csi.alibabacloud.com")
	if !exists {
		t.Fatalf("nas driver not registered")
	}
	if _, ok := nasProvider.(*MountProvider); !ok {
		t.Errorf("nas driver expected *MountProvider, got %T", nasProvider)
	}
}

// resetInitializeProviderFuncs resets the global initializeProviderFuncs slice for testing
func resetInitializeProviderFuncs() {
	initializeProviderFuncs = []initProviderFunc{}
}
