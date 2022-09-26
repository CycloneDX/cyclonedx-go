// This file is part of CycloneDX Go
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an “AS IS” BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) OWASP Foundation. All Rights Reserved.

package cyclonedx

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/bradleyjkemp/cupaloy/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var snapShooter = cupaloy.NewDefaultConfig().
	WithOptions(cupaloy.SnapshotSubdirectory("./testdata/snapshots"))

func TestBool(t *testing.T) {
	assert.Equal(t, true, *Bool(true))
	assert.Equal(t, false, *Bool(false))
}

func TestMediaType_WithVersion(t *testing.T) {
	t.Run("ShouldReturnVersionedMediaType", func(t *testing.T) {
		res, err := MediaTypeJSON.WithVersion(SpecVersion1_2)
		require.NoError(t, err)
		require.Equal(t, "application/vnd.cyclonedx+json; version=1.2", res)
	})

	t.Run("ShouldReturnErrorForSpecLowerThan1.2AndJSON", func(t *testing.T) {
		_, err := MediaTypeJSON.WithVersion(SpecVersion1_1)
		require.Error(t, err)
	})
}

func TestVulnerability_Properties(t *testing.T) {
	// GIVEN
	properties := []Property{}
	vuln := Vulnerability{
		Properties: &properties,
	}

	// EXPECT
	assert.Equal(t, 0, len(*vuln.Properties))
}

func assertValidBOM(t *testing.T, bomFilePath string, version SpecVersion) {
	inputFormat := "xml"
	if strings.HasSuffix(bomFilePath, ".json") {
		inputFormat = "json"
	}
	inputVersion := fmt.Sprintf("v%s", strings.ReplaceAll(version.String(), ".", "_"))
	valCmd := exec.Command("cyclonedx", "validate", "--input-file", bomFilePath, "--input-format", inputFormat, "--input-version", inputVersion, "--fail-on-errors")
	valOut, err := valCmd.CombinedOutput()
	if !assert.NoError(t, err) {
		// Provide some context when test is failing
		fmt.Printf("validation error: %s\n", string(valOut))
	}
}
