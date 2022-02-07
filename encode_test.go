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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBOMEncoder(t *testing.T) {
	assert.IsType(t, &jsonBOMEncoder{}, NewBOMEncoder(nil, BOMFileFormatJSON))
	assert.IsType(t, &xmlBOMEncoder{}, NewBOMEncoder(nil, BOMFileFormatXML))
}

func TestJsonBOMEncoder_SetPretty(t *testing.T) {
	buf := new(bytes.Buffer)
	encoder := NewBOMEncoder(buf, BOMFileFormatJSON)
	encoder.SetPretty(true)

	bom := NewBOM()
	bom.Metadata = &Metadata{
		Authors: &[]OrganizationalContact{
			{
				Name: "authorName",
			},
		},
	}

	require.NoError(t, encoder.Encode(bom))

	assert.Equal(t, `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "metadata": {
    "authors": [
      {
        "name": "authorName"
      }
    ]
  }
}
`, buf.String())
}

func TestXmlBOMEncoder_SetPretty(t *testing.T) {
	buf := new(bytes.Buffer)
	encoder := NewBOMEncoder(buf, BOMFileFormatXML)
	encoder.SetPretty(true)

	bom := NewBOM()
	bom.Metadata = &Metadata{
		Authors: &[]OrganizationalContact{
			{
				Name: "authorName",
			},
		},
	}

	require.NoError(t, encoder.Encode(bom))

	assert.Equal(t, `<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">
  <metadata>
    <authors>
      <author>
        <name>authorName</name>
      </author>
    </authors>
  </metadata>
</bom>`, buf.String())
}
