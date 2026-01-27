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
	"fmt"
	"io"
	"os"
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
  "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
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

func TestJsonBOMEncoder_SetIndentTab(t *testing.T) {
	buf := new(bytes.Buffer)
	encoder := NewBOMEncoder(buf, BOMFileFormatJSON)
	encoder.SetPretty(true)
	encoder.SetIndent("\t")

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
	"$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
	"bomFormat": "CycloneDX",
	"specVersion": "1.6",
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

func TestJsonBOMEncoder_SetEscapeHTML_true(t *testing.T) {
	buf := new(bytes.Buffer)
	encoder := NewBOMEncoder(buf, BOMFileFormatJSON)
	encoder.SetPretty(true)
	encoder.SetEscapeHTML(true)

	bom := NewBOM()
	bom.Metadata = &Metadata{
		Authors: &[]OrganizationalContact{
			{
				Name: "some&<\"Name",
			},
		},
	}

	require.NoError(t, encoder.Encode(bom))

	assert.Equal(t, `{
  "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "authors": [
      {
        "name": "some\u0026\u003c\"Name"
      }
    ]
  }
}
`, buf.String())
}

func TestJsonBOMEncoder_SetEscapeHTML_false(t *testing.T) {
	buf := new(bytes.Buffer)
	encoder := NewBOMEncoder(buf, BOMFileFormatJSON)
	encoder.SetPretty(true)
	encoder.SetEscapeHTML(false)

	bom := NewBOM()
	bom.Metadata = &Metadata{
		Authors: &[]OrganizationalContact{
			{
				Name: "some+<&\"Name",
			},
		},
	}

	require.NoError(t, encoder.Encode(bom))

	assert.Equal(t, `{
  "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "authors": [
      {
        "name": "some+<&\"Name"
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
		Properties: &[]Property{
			{
				Name:  "XML",
				Value: "<xml>in here</xml>",
			},
			{
				Name:  "Specials",
				Value: "Special chars: < & > \"",
			},
		},
	}

	require.NoError(t, encoder.Encode(bom))

	assert.Equal(t, `<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">
  <metadata>
    <authors>
      <author>
        <name>authorName</name>
      </author>
    </authors>
    <properties>
      <property name="XML">&lt;xml&gt;in here&lt;/xml&gt;</property>
      <property name="Specials">Special chars: &lt; &amp; &gt; &#34;</property>
    </properties>
  </metadata>
</bom>`, buf.String())
}

func TestXmlBOMEncoder_SetIndentTab(t *testing.T) {
	buf := new(bytes.Buffer)
	encoder := NewBOMEncoder(buf, BOMFileFormatXML)
	encoder.SetPretty(true)
	encoder.SetIndent("\t")

	bom := NewBOM()
	bom.Metadata = &Metadata{
		Authors: &[]OrganizationalContact{
			{
				Name: "authorName",
			},
		},
		Properties: &[]Property{
			{
				Name:  "XML",
				Value: "<xml>in here</xml>",
			},
			{
				Name:  "Specials",
				Value: "Special chars: < & > \"",
			},
		},
	}

	require.NoError(t, encoder.Encode(bom))

	assert.Equal(t, `<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">
	<metadata>
		<authors>
			<author>
				<name>authorName</name>
			</author>
		</authors>
		<properties>
			<property name="XML">&lt;xml&gt;in here&lt;/xml&gt;</property>
			<property name="Specials">Special chars: &lt; &amp; &gt; &#34;</property>
		</properties>
	</metadata>
</bom>`, buf.String())
}

func TestJsonBOMEncoder_EncodeVersion(t *testing.T) {
	t.Run(SpecVersion1_0.String(), func(t *testing.T) {
		err := NewBOMEncoder(io.Discard, BOMFileFormatJSON).EncodeVersion(NewBOM(), SpecVersion1_0)
		require.Error(t, err)
		require.ErrorContains(t, err, "not supported")
	})

	t.Run(SpecVersion1_1.String(), func(t *testing.T) {
		err := NewBOMEncoder(io.Discard, BOMFileFormatJSON).EncodeVersion(NewBOM(), SpecVersion1_1)
		require.Error(t, err)
		require.ErrorContains(t, err, "not supported")
	})

	for _, version := range []SpecVersion{SpecVersion1_2, SpecVersion1_3, SpecVersion1_4, SpecVersion1_5, SpecVersion1_6} {
		t.Run(version.String(), func(t *testing.T) {
			// Read original BOM JSON
			inputFile, err := os.Open("./testdata/valid-bom.json")
			require.NoError(t, err)

			// Decode BOM
			var bom BOM
			require.NoError(t, NewBOMDecoder(inputFile, BOMFileFormatJSON).Decode(&bom))
			inputFile.Close()

			// Prepare encoding destination
			buf := bytes.Buffer{}

			// Encode BOM again, for a specific version
			err = NewBOMEncoder(&buf, BOMFileFormatJSON).
				SetPretty(true).
				EncodeVersion(&bom, version)
			require.NoError(t, err)

			// Sanity checks: BOM has to be valid
			assertValidBOM(t, buf.Bytes(), BOMFileFormatJSON, version)

			// Compare with snapshot
			require.NoError(t, snapShooter.SnapshotMulti(fmt.Sprintf("%s.bom.json", version), buf.String()))
		})
	}
}

func TestXmlBOMEncoder_EncodeVersion(t *testing.T) {
	for _, version := range []SpecVersion{SpecVersion1_0, SpecVersion1_1, SpecVersion1_2, SpecVersion1_3, SpecVersion1_4, SpecVersion1_5, SpecVersion1_6} {
		t.Run(version.String(), func(t *testing.T) {
			// Read original BOM JSON
			inputFile, err := os.Open("./testdata/valid-bom.xml")
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
				EncodeVersion(&bom, version)
			require.NoError(t, err)

			// Sanity checks: BOM has to be valid
			require.NoError(t, snapShooter.SnapshotMulti(fmt.Sprintf("%s.bom.xml", version), buf.String()))

			// Compare with snapshot
			assertValidBOM(t, buf.Bytes(), BOMFileFormatXML, version)
		})
	}
}
