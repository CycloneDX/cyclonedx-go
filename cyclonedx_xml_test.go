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
	t.Run("Empty", func(t *testing.T) {
		bomRef := BOMReference("")
		xmlBytes, err := xml.Marshal(bomRef)
		require.NoError(t, err)
		require.Equal(t, "<BOMReference ref=\"\"></BOMReference>", string(xmlBytes))
	})

	t.Run("NonEmpty", func(t *testing.T) {
		bomRef := BOMReference("bomRef")
		xmlBytes, err := xml.Marshal(bomRef)
		require.NoError(t, err)
		require.Equal(t, "<BOMReference ref=\"bomRef\"></BOMReference>", string(xmlBytes))
	})
}

func TestBOMReference_UnmarshalXML(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		bomRef := new(BOMReference)
		err := xml.Unmarshal([]byte("<BOMReference ref=\"\"></BOMReference>"), bomRef)
		require.NoError(t, err)
		require.Equal(t, "", string(*bomRef))
	})

	t.Run("NonEmpty", func(t *testing.T) {
		bomRef := new(BOMReference)
		err := xml.Unmarshal([]byte("<BOMReference ref=\"bomRef\"></BOMReference>"), bomRef)
		require.NoError(t, err)
		require.Equal(t, "bomRef", string(*bomRef))
	})
}

func TestCopyright_MarshalXML(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		copyright := Copyright{}
		xmlBytes, err := xml.Marshal(copyright)
		require.NoError(t, err)
		require.Equal(t, "<Copyright></Copyright>", string(xmlBytes))
	})

	t.Run("NonEmpty", func(t *testing.T) {
		copyright := Copyright{Text: "copyright"}
		xmlBytes, err := xml.Marshal(copyright)
		require.NoError(t, err)
		require.Equal(t, "<Copyright>copyright</Copyright>", string(xmlBytes))
	})
}

func TestCopyright_UnmarshalXML(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		copyright := new(Copyright)
		err := xml.Unmarshal([]byte("<Copyright></Copyright>"), copyright)
		require.NoError(t, err)
		require.Equal(t, "", copyright.Text)
	})

	t.Run("NonEmpty", func(t *testing.T) {
		copyright := new(Copyright)
		err := xml.Unmarshal([]byte("<Copyright>copyright</Copyright>"), copyright)
		require.NoError(t, err)
		require.Equal(t, "copyright", copyright.Text)
	})
}

func TestDependency_MarshalXML(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		dependency := Dependency{}
		xmlBytes, err := xml.Marshal(dependency)
		require.NoError(t, err)
		require.Equal(t, `<Dependency ref=""></Dependency>`, string(xmlBytes))
	})

	t.Run("EmptyDependencies", func(t *testing.T) {
		dependency := Dependency{
			Ref:          "dependencyRef",
			Dependencies: &[]string{},
		}
		xmlBytes, err := xml.Marshal(dependency)
		require.NoError(t, err)
		require.Equal(t, `<Dependency ref="dependencyRef"></Dependency>`, string(xmlBytes))
	})

	t.Run("WithDependencies", func(t *testing.T) {
		dependency := Dependency{
			Ref: "dependencyRef",
			Dependencies: &[]string{
				"transitiveDependencyRef",
			},
		}
		xmlBytes, err := xml.Marshal(dependency)
		require.NoError(t, err)
		require.Equal(t, `<Dependency ref="dependencyRef"><dependency ref="transitiveDependencyRef"></dependency></Dependency>`, string(xmlBytes))
	})
}

func TestDependency_UnmarshalXML(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		dependency := Dependency{}
		err := xml.Unmarshal([]byte(`<Dependency></Dependency>`), &dependency)
		require.NoError(t, err)
		require.Equal(t, "", dependency.Ref)
		require.Nil(t, dependency.Dependencies)
	})

	t.Run("EmptyDependencies", func(t *testing.T) {
		dependency := Dependency{}
		err := xml.Unmarshal([]byte(`<Dependency ref="dependencyRef"></Dependency>`), &dependency)
		require.NoError(t, err)
		require.Equal(t, "dependencyRef", dependency.Ref)
		require.Nil(t, dependency.Dependencies)
	})

	t.Run("WithDependencies", func(t *testing.T) {
		dependency := Dependency{}
		err := xml.Unmarshal([]byte(`<Dependency ref="dependencyRef"><dependency ref="transitiveDependencyRef"></dependency></Dependency>`), &dependency)
		require.NoError(t, err)
		require.Equal(t, "dependencyRef", dependency.Ref)
		require.Equal(t, 1, len(*dependency.Dependencies))
		require.Equal(t, "transitiveDependencyRef", (*dependency.Dependencies)[0])
	})
}

func TestEnvironmentVariables_MarshalXML(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		envVars := EnvironmentVariables{}
		xmlBytes, err := xml.Marshal(envVars)
		require.NoError(t, err)
		require.Equal(t, "", string(xmlBytes))
	})

	t.Run("NonEmpty", func(t *testing.T) {
		envVars := EnvironmentVariables{
			EnvironmentVariableChoice{
				Property: &Property{
					Name:  "foo",
					Value: "bar",
				},
			},
			EnvironmentVariableChoice{
				Value: "baz",
			},
		}
		xmlBytes, err := xml.Marshal(envVars)
		require.NoError(t, err)
		require.Equal(t, `<EnvironmentVariables><environmentVar name="foo">bar</environmentVar><value>baz</value></EnvironmentVariables>`, string(xmlBytes))
	})

	t.Run("WithChoiceHavingBothPropertyAndValue", func(t *testing.T) {
		envVars := EnvironmentVariables{
			EnvironmentVariableChoice{
				Property: &Property{
					Name:  "foo",
					Value: "bar",
				},
				Value: "baz",
			},
		}
		_, err := xml.Marshal(envVars)
		require.EqualError(t, err, "either property or value must be set, but not both")
	})
}

func TestEnvironmentVariables_UnmarshalXML(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		envVars := EnvironmentVariables{}
		err := xml.Unmarshal([]byte("<EnvironmentVariables></EnvironmentVariables>"), &envVars)
		require.NoError(t, err)
		require.Empty(t, envVars)
	})

	t.Run("NonEmpty", func(t *testing.T) {
		envVars := EnvironmentVariables{}
		err := xml.Unmarshal([]byte(`
<EnvironmentVariables>
  <environmentVar name="foo">bar</environmentVar>
  <value>baz</value>
</EnvironmentVariables>`), &envVars)
		require.NoError(t, err)
		require.Len(t, envVars, 2)
		require.NotNil(t, envVars[0].Property)
		require.Equal(t, "foo", envVars[0].Property.Name)
		require.Equal(t, "bar", envVars[0].Property.Value)
		require.Empty(t, envVars[0].Value)
		require.Nil(t, envVars[1].Property)
		require.Equal(t, "baz", envVars[1].Value)
	})
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

func TestMLDatasetChoice_MarshalXML(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		choice := MLDatasetChoice{}
		xmlBytes, err := xml.Marshal(choice)
		require.NoError(t, err)
		require.Equal(t, "", string(xmlBytes))
	})

	t.Run("WithRef", func(t *testing.T) {
		choice := MLDatasetChoice{Ref: "foo"}
		xmlBytes, err := xml.Marshal(choice)
		require.NoError(t, err)
		require.Equal(t, `<MLDatasetChoice><ref>foo</ref></MLDatasetChoice>`, string(xmlBytes))
	})

	t.Run("WithComponentData", func(t *testing.T) {
		choice := MLDatasetChoice{
			ComponentData: &ComponentData{
				BOMRef: "foo",
				Name:   "bar",
			},
		}
		xmlBytes, err := xml.Marshal(choice)
		require.NoError(t, err)
		require.Equal(t, `<MLDatasetChoice bom-ref="foo"><name>bar</name></MLDatasetChoice>`, string(xmlBytes))
	})

	t.Run("WithRefAndComponentData", func(t *testing.T) {
		choice := MLDatasetChoice{
			Ref: "foo",
			ComponentData: &ComponentData{
				BOMRef: "bar",
				Name:   "baz",
			},
		}
		xmlBytes, err := xml.Marshal(choice)
		require.NoError(t, err)
		require.Equal(t, `<MLDatasetChoice><ref>foo</ref></MLDatasetChoice>`, string(xmlBytes))
	})
}

func TestMLDatasetChoice_UnmarshalXML(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		var choice MLDatasetChoice
		err := xml.Unmarshal([]byte(`<MLDatasetChoice></MLDatasetChoice>`), &choice)
		require.NoError(t, err)
		require.Equal(t, MLDatasetChoice{}, choice)
	})

	t.Run("WithRef", func(t *testing.T) {
		var choice MLDatasetChoice
		err := xml.Unmarshal([]byte(`<MLDatasetChoice><ref>foo</ref></MLDatasetChoice>`), &choice)
		require.NoError(t, err)
		require.Equal(t, "foo", choice.Ref)
		require.Nil(t, choice.ComponentData)
	})

	t.Run("WithComponentData", func(t *testing.T) {
		var choice MLDatasetChoice
		err := xml.Unmarshal([]byte(`<MLDatasetChoice bom-ref="foo"><name>bar</name></MLDatasetChoice>`), &choice)
		require.NoError(t, err)
		require.Empty(t, choice.Ref)
		require.NotNil(t, choice.ComponentData)
		require.Equal(t, "foo", choice.ComponentData.BOMRef)
		require.Equal(t, "bar", choice.ComponentData.Name)
	})

	t.Run("WithRefAndComponentData", func(t *testing.T) {
		var choice MLDatasetChoice
		err := xml.Unmarshal([]byte(`<MLDatasetChoice bom-ref="bar"><ref>foo</ref><name>baz</name></MLDatasetChoice>`), &choice)
		require.NoError(t, err)
		require.Equal(t, "foo", choice.Ref)
		require.Nil(t, choice.ComponentData)
	})
}
