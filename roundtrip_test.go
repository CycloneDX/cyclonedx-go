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
// Copyright (c) Niklas Düster. All Rights Reserved.

package cyclonedx

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bradleyjkemp/cupaloy/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var roundTripSnapshotter = cupaloy.NewDefaultConfig().
	WithOptions(cupaloy.SnapshotSubdirectory("./testdata/snapshots"))

func TestRoundTripJSON(t *testing.T) {
	bomFilePaths, err := filepath.Glob("./testdata/*.json")
	require.NoError(t, err)

	for _, bomFilePath := range bomFilePaths {
		// Read original BOM JSON
		bomFile, err := os.Open(bomFilePath)
		require.NoError(t, err)

		// Decode BOM
		bom := new(BOM)
		require.NoError(t, NewBOMDecoder(bomFile, BOMFileFormatJSON).Decode(bom))
		bomFile.Close()

		// Encode BOM again
		buf := new(bytes.Buffer)
		tempFile, err := ioutil.TempFile("", t.Name()+".*."+filepath.Base(bomFilePath))
		require.NoError(t, err)

		encoder := NewBOMEncoder(io.MultiWriter(buf, tempFile), BOMFileFormatJSON)
		encoder.SetPretty(true)
		require.NoError(t, encoder.Encode(bom))
		tempFile.Close() // Required for CLI to be able to access the file

		// Sanity checks: BOM has to be valid
		assertValidBOM(t, tempFile.Name())
		os.Remove(tempFile.Name())

		// Compare with snapshot
		assert.NoError(t, roundTripSnapshotter.SnapshotMulti(filepath.Base(bomFilePath), buf.String()))
	}
}

func TestRoundTripXML(t *testing.T) {
	bomFilePaths, err := filepath.Glob("./testdata/*.xml")
	require.NoError(t, err)

	for _, bomFilePath := range bomFilePaths {
		// Read original BOM XML
		bomFile, err := os.Open(bomFilePath)
		require.NoError(t, err)

		// Decode BOM
		bom := new(BOM)
		require.NoError(t, NewBOMDecoder(bomFile, BOMFileFormatXML).Decode(bom))
		bomFile.Close()

		// Encode BOM again
		buf := new(bytes.Buffer)
		tempFile, err := ioutil.TempFile("", t.Name()+".*."+filepath.Base(bomFilePath))
		require.NoError(t, err)

		encoder := NewBOMEncoder(io.MultiWriter(buf, tempFile), BOMFileFormatXML)
		encoder.SetPretty(true)
		require.NoError(t, encoder.Encode(bom))
		tempFile.Close() // Required for CLI to be able to access the file

		// Sanity check: BOM has to be valid
		assertValidBOM(t, tempFile.Name())
		os.Remove(tempFile.Name())

		// Compare with snapshot
		assert.NoError(t, roundTripSnapshotter.SnapshotMulti(filepath.Base(bomFilePath), buf.String()))
	}
}

func assertValidBOM(t *testing.T, bomFilePath string) {
	inputFormat := "xml_v1_3"
	if strings.HasSuffix(bomFilePath, ".json") {
		inputFormat = "json_v1_3"
	}
	valCmd := exec.Command("cyclonedx", "validate", "--input-file", bomFilePath, "--input-format", inputFormat, "--fail-on-errors")
	valOut, err := valCmd.CombinedOutput()
	if !assert.NoError(t, err) {
		// Provide some context when test is failing
		fmt.Printf("validation error: %s\n", string(valOut))
	}
}
