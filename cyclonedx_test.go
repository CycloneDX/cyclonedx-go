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
	"encoding/json"
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBool(t *testing.T) {
	assert.Equal(t, true, *Bool(true))
	assert.Equal(t, false, *Bool(false))
}

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

func TestDependency_MarshalJSON(t *testing.T) {
	// Marshal empty dependency
	dependency := Dependency{}
	jsonBytes, err := json.Marshal(dependency)
	assert.NoError(t, err)
	assert.Equal(t, "{\"ref\":\"\"}", string(jsonBytes))

	// Marshal dependency with empty dependencies
	dependency = Dependency{
		Ref:          "dependencyRef",
		Dependencies: &[]Dependency{},
	}
	jsonBytes, err = json.Marshal(dependency)
	assert.NoError(t, err)
	assert.Equal(t, "{\"ref\":\"dependencyRef\"}", string(jsonBytes))

	// Marshal dependency with dependencies
	dependency = Dependency{
		Ref: "dependencyRef",
		Dependencies: &[]Dependency{
			{Ref: "transitiveDependencyRef"},
		},
	}
	jsonBytes, err = json.Marshal(dependency)
	assert.NoError(t, err)
	assert.Equal(t, "{\"ref\":\"dependencyRef\",\"dependsOn\":[\"transitiveDependencyRef\"]}", string(jsonBytes))
}

func TestDependency_UnmarshalJSON(t *testing.T) {
	// Unmarshal empty dependency
	dependency := new(Dependency)
	err := json.Unmarshal([]byte("{}"), dependency)
	assert.NoError(t, err)
	assert.Equal(t, "", dependency.Ref)
	assert.Nil(t, dependency.Dependencies)

	// Unmarshal dependency with empty dependencies
	dependency = new(Dependency)
	err = json.Unmarshal([]byte("{\"ref\":\"dependencyRef\",\"dependsOn\":[]}"), dependency)
	assert.NoError(t, err)
	assert.Equal(t, "dependencyRef", dependency.Ref)
	assert.Nil(t, dependency.Dependencies)

	// Unmarshal dependency with dependencies
	dependency = new(Dependency)
	err = json.Unmarshal([]byte("{\"ref\":\"dependencyRef\",\"dependsOn\":[\"transitiveDependencyRef\"]}"), dependency)
	assert.NoError(t, err)
	assert.Equal(t, "dependencyRef", dependency.Ref)
	assert.Equal(t, 1, len(*dependency.Dependencies))
	assert.Equal(t, "transitiveDependencyRef", (*dependency.Dependencies)[0].Ref)
}

func TestLicenseChoice_MarshalJSON(t *testing.T) {
	// Marshal license
	choice := LicenseChoice{
		License: &License{
			ID:   "licenseID",
			Name: "licenseName",
			URL:  "licenseURL",
		},
	}
	jsonBytes, err := json.Marshal(choice)
	assert.NoError(t, err)
	assert.Equal(t, "{\"license\":{\"id\":\"licenseID\",\"name\":\"licenseName\",\"url\":\"licenseURL\"}}", string(jsonBytes))

	// Marshal expression
	choice = LicenseChoice{
		Expression: "expressionValue",
	}
	jsonBytes, err = json.Marshal(choice)
	assert.NoError(t, err)
	assert.Equal(t, "{\"expression\":\"expressionValue\"}", string(jsonBytes))
}

func TestLicenseChoice_MarshalXML(t *testing.T) {
	// Marshal license
	choice := LicenseChoice{
		License: &License{
			ID:   "licenseID",
			Name: "licenseName",
			URL:  "licenseURL",
		},
	}
	xmlBytes, err := xml.Marshal(choice)
	assert.NoError(t, err)
	assert.Equal(t, "<license><id>licenseID</id><name>licenseName</name><url>licenseURL</url></license>", string(xmlBytes))

	// Marshal expression
	choice = LicenseChoice{
		Expression: "expressionValue",
	}
	xmlBytes, err = xml.Marshal(choice)
	assert.NoError(t, err)
	assert.Equal(t, "<expression>expressionValue</expression>", string(xmlBytes))

	// Should return error when both license and expression are set
	choice = LicenseChoice{
		License: &License{
			ID: "licenseID",
		},
		Expression: "expressionValue",
	}
	_, err = xml.Marshal(choice)
	assert.Error(t, err)

	// Should encode nothing when neither license nor expression are set
	choice = LicenseChoice{}
	xmlBytes, err = xml.Marshal(choice)
	assert.NoError(t, err)
	assert.Nil(t, xmlBytes)
}

func TestLicenseChoice_UnmarshalJSON(t *testing.T) {
	// Unmarshal license
	choice := new(LicenseChoice)
	err := json.Unmarshal([]byte("{\"license\":{\"id\":\"licenseID\",\"name\":\"licenseName\",\"url\":\"licenseURL\"}}"), choice)
	assert.NoError(t, err)
	assert.NotNil(t, choice.License)
	assert.Equal(t, "", choice.Expression)

	// Unmarshal expression
	choice = new(LicenseChoice)
	err = json.Unmarshal([]byte("{\"expression\":\"expressionValue\"}"), choice)
	assert.NoError(t, err)
	assert.Nil(t, choice.License)
	assert.Equal(t, "expressionValue", choice.Expression)
}

func TestLicenseChoice_UnmarshalXML(t *testing.T) {
	// Unmarshal license
	choice := new(LicenseChoice)
	err := xml.Unmarshal([]byte("<license><id>licenseID</id><name>licenseName</name><url>licenseURL</url></license>"), choice)
	assert.NoError(t, err)
	assert.NotNil(t, choice.License)
	assert.Equal(t, "", choice.Expression)

	// Unmarshal expression
	choice = new(LicenseChoice)
	err = xml.Unmarshal([]byte("<expression>expressionValue</expression>"), choice)
	assert.NoError(t, err)
	assert.Nil(t, choice.License)
	assert.Equal(t, "expressionValue", choice.Expression)

	// Should return error when input is neither license nor expression
	choice = new(LicenseChoice)
	err = xml.Unmarshal([]byte("<somethingElse>expressionValue</somethingElse>"), choice)
	assert.Error(t, err)
}
