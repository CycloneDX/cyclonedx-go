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
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBOMReference_MarshalXML(t *testing.T) {
	// Marshal empty bomRef
	bomRef := BOMReference("")
	xmlBytes, err := xml.Marshal(bomRef)
	assert.NoError(t, err)
	assert.Equal(t, "<BOMReference ref=\"\"></BOMReference>", string(xmlBytes))

	// Marshal bomRef
	bomRef = "bomRef"
	xmlBytes, err = xml.Marshal(bomRef)
	assert.NoError(t, err)
	assert.Equal(t, "<BOMReference ref=\"bomRef\"></BOMReference>", string(xmlBytes))
}

func TestBOMReference_UnmarshalXML(t *testing.T) {
	// Unmarshal empty bomRef
	bomRef := new(BOMReference)
	err := xml.Unmarshal([]byte("<BOMReference ref=\"\"></BOMReference>"), bomRef)
	require.NoError(t, err)
	require.Equal(t, "", string(*bomRef))

	// Unmarshal bomRef
	err = xml.Unmarshal([]byte("<BOMReference ref=\"bomRef\"></BOMReference>"), bomRef)
	require.NoError(t, err)
	require.Equal(t, "bomRef", string(*bomRef))
}

func TestCopyright_MarshalXML(t *testing.T) {
	// Marshal empty copyright
	copyright := Copyright{}
	xmlBytes, err := xml.Marshal(copyright)
	require.NoError(t, err)
	require.Equal(t, "<Copyright></Copyright>", string(xmlBytes))

	// Marshal copyright
	copyright.Text = "copyright"
	xmlBytes, err = xml.Marshal(copyright)
	require.NoError(t, err)
	require.Equal(t, "<Copyright>copyright</Copyright>", string(xmlBytes))
}

func TestCopyright_UnmarshalXML(t *testing.T) {
	// Unmarshal empty copyright
	copyright := new(Copyright)
	err := xml.Unmarshal([]byte("<Copyright></Copyright>"), copyright)
	require.NoError(t, err)
	require.Equal(t, "", copyright.Text)

	// Unmarshal copyright
	err = xml.Unmarshal([]byte("<Copyright>copyright</Copyright>"), copyright)
	require.NoError(t, err)
	require.Equal(t, "copyright", copyright.Text)
}

func TestLicenses_MarshalXML(t *testing.T) {
	// Marshal license and expressions
	licenses := Licenses{
		LicenseChoice{
			Expression: "expressionValue1",
		},
		LicenseChoice{
			License: &License{
				ID:  "licenseID",
				URL: "licenseURL",
			},
		},
		LicenseChoice{
			Expression: "expressionValue2",
		},
	}
	xmlBytes, err := xml.MarshalIndent(licenses, "", "  ")
	assert.NoError(t, err)
	assert.Equal(t, `<Licenses>
  <expression>expressionValue1</expression>
  <license>
    <id>licenseID</id>
    <url>licenseURL</url>
  </license>
  <expression>expressionValue2</expression>
</Licenses>`, string(xmlBytes))

	// Should return error when both license and expression are set on an element
	licenses = Licenses{
		LicenseChoice{
			License: &License{
				ID: "licenseID",
			},
			Expression: "expressionValue",
		},
	}
	_, err = xml.Marshal(licenses)
	assert.Error(t, err)

	// Should encode nothing when empty
	licenses = Licenses{}
	xmlBytes, err = xml.Marshal(licenses)
	assert.NoError(t, err)
	assert.Nil(t, xmlBytes)
}

func TestLicenses_UnmarshalXML(t *testing.T) {
	// Unmarshal license and expressions
	licenses := new(Licenses)
	err := xml.Unmarshal([]byte(`
<Licenses>
  <expression>expressionValue1</expression>
  <license>
    <id>licenseID</id>
    <url>licenseURL</url>
  </license>
  <expression>expressionValue2</expression>
</Licenses>`), licenses)
	assert.NoError(t, err)
	assert.Len(t, *licenses, 3)
	assert.Nil(t, (*licenses)[0].License)
	assert.Equal(t, "expressionValue1", (*licenses)[0].Expression)
	assert.NotNil(t, (*licenses)[1].License)
	assert.Equal(t, "licenseID", (*licenses)[1].License.ID)
	assert.Equal(t, "licenseURL", (*licenses)[1].License.URL)
	assert.Empty(t, (*licenses)[1].Expression)
	assert.Nil(t, (*licenses)[2].License)
	assert.Equal(t, "expressionValue2", (*licenses)[2].Expression)

	// Unmarshal empty licenses
	licenses = new(Licenses)
	err = xml.Unmarshal([]byte("<Licenses></Licenses>"), licenses)
	assert.NoError(t, err)
	assert.Empty(t, *licenses)

	// Should return error when an element is neither license nor expression
	licenses = new(Licenses)
	err = xml.Unmarshal([]byte("<Licenses><somethingElse>expressionValue</somethingElse></Licenses>"), licenses)
	assert.Error(t, err)
}
