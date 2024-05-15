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
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoundTripJSON(t *testing.T) {
	bomFilePaths, err := filepath.Glob("./testdata/*.json")
	require.NoError(t, err)

	for _, bomFilePath := range bomFilePaths {
		t.Run(filepath.Base(bomFilePath), func(t *testing.T) {
			// Read original BOM JSON
			inputFile, err := os.Open(bomFilePath)
			require.NoError(t, err)

			// Decode BOM
			var bom BOM
			require.NoError(t, NewBOMDecoder(inputFile, BOMFileFormatJSON).Decode(&bom))
			inputFile.Close()

			// Prepare encoding destination
			buf := bytes.Buffer{}

			// Encode BOM again
			err = NewBOMEncoder(&buf, BOMFileFormatJSON).
				SetPretty(true).
				Encode(&bom)
			require.NoError(t, err)

			// Sanity checks: BOM has to be valid
			assertValidBOM(t, buf.Bytes(), BOMFileFormatJSON, SpecVersion1_6)

			// Compare with snapshot
			assert.NoError(t, snapShooter.SnapshotMulti(filepath.Base(bomFilePath), buf.String()))
		})
	}
}

func TestRoundTripXML(t *testing.T) {
	bomFilePaths, err := filepath.Glob("./testdata/*.xml")
	require.NoError(t, err)

	for _, bomFilePath := range bomFilePaths {
		t.Run(filepath.Base(bomFilePath), func(t *testing.T) {
			// Read original BOM XML
			inputFile, err := os.Open(bomFilePath)
			require.NoError(t, err)

			// Decode BOM
			var bom BOM
			require.NoError(t, NewBOMDecoder(inputFile, BOMFileFormatXML).Decode(&bom))
			inputFile.Close()

			// Prepare encoding destination
			buf := bytes.Buffer{}

			// Encode BOM again
			err = NewBOMEncoder(&buf, BOMFileFormatXML).
				SetPretty(true).
				Encode(&bom)
			require.NoError(t, err)

			// Sanity check: BOM has to be valid
			assertValidBOM(t, buf.Bytes(), BOMFileFormatXML, SpecVersion1_6)

			// Compare with snapshot
			assert.NoError(t, snapShooter.SnapshotMulti(filepath.Base(bomFilePath), buf.String()))
		})
	}
}
