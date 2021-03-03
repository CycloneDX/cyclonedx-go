package cyclonedx

import (
	"encoding/json"
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBool(t *testing.T) {
	assert.Equal(t, true, *Bool(true))
	assert.Equal(t, false, *Bool(false))
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
