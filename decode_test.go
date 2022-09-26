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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBOMDecoder(t *testing.T) {
	assert.IsType(t, &jsonBOMDecoder{}, NewBOMDecoder(nil, BOMFileFormatJSON))
	assert.IsType(t, &xmlBOMDecoder{}, NewBOMDecoder(nil, BOMFileFormatXML))
}

func TestXmlBOMDecoder_Decode(t *testing.T) {
	t.Run("ShouldSetSpecVersion", func(t *testing.T) {
		testCases := []struct {
			bomContent  string
			specVersion SpecVersion
		}{
			{
				bomContent:  `<?xml version="1.0"?><bom version="1" xmlns="http://cyclonedx.org/schema/bom/1.0"></bom>`,
				specVersion: SpecVersion1_0,
			},
			{
				bomContent:  `<?xml version="1.0"?><bom version="1" xmlns="http://cyclonedx.org/schema/bom/1.1"></bom>`,
				specVersion: SpecVersion1_1,
			},
			{
				bomContent:  `<?xml version="1.0"?><bom version="1" xmlns="http://cyclonedx.org/schema/bom/1.2"></bom>`,
				specVersion: SpecVersion1_2,
			},
			{
				bomContent:  `<?xml version="1.0"?><bom version="1" xmlns="http://cyclonedx.org/schema/bom/1.3"></bom>`,
				specVersion: SpecVersion1_3,
			},
			{
				bomContent:  `<?xml version="1.0"?><bom version="1" xmlns="http://cyclonedx.org/schema/bom/1.4"></bom>`,
				specVersion: SpecVersion1_4,
			},
			{
				bomContent:  `<?xml version="1.0"?><bom version="1" xmlns="http://cyclonedx.org/schema/bom/666"></bom>`,
				specVersion: SpecVersion(0),
			},
		}

		for _, tc := range testCases {
			t.Run(tc.specVersion.String(), func(t *testing.T) {
				var bom BOM
				err := NewBOMDecoder(strings.NewReader(tc.bomContent), BOMFileFormatXML).Decode(&bom)
				require.NoError(t, err)
				require.Equal(t, tc.specVersion, bom.SpecVersion)
			})
		}
	})
}
