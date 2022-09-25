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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
