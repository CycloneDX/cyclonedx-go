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

import "encoding/json"

// dependencyJSON is temporarily used for marshalling and unmarshalling Dependency instances to and from JSON
type dependencyJSON struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

func (d Dependency) MarshalJSON() ([]byte, error) {
	if d.Dependencies == nil || len(*d.Dependencies) == 0 {
		return json.Marshal(&dependencyJSON{
			Ref: d.Ref,
		})
	}

	dependencyRefs := make([]string, len(*d.Dependencies))
	for i, dependency := range *d.Dependencies {
		dependencyRefs[i] = dependency.Ref
	}

	return json.Marshal(&dependencyJSON{
		Ref:       d.Ref,
		DependsOn: dependencyRefs,
	})
}

func (d *Dependency) UnmarshalJSON(bytes []byte) error {
	dependency := new(dependencyJSON)
	if err := json.Unmarshal(bytes, dependency); err != nil {
		return err
	}
	d.Ref = dependency.Ref

	if len(dependency.DependsOn) == 0 {
		return nil
	}

	dependencies := make([]Dependency, len(dependency.DependsOn))
	for i, dep := range dependency.DependsOn {
		dependencies[i] = Dependency{
			Ref: dep,
		}
	}
	d.Dependencies = &dependencies

	return nil
}

func (sv SpecVersion) MarshalJSON() ([]byte, error) {
	return json.Marshal(sv.String())
}

func (sv *SpecVersion) UnmarshalJSON(bytes []byte) error {
	var v string
	err := json.Unmarshal(bytes, &v)
	if err != nil {
		return err
	}

	switch v {
	case SpecVersion1_0.String():
		*sv = SpecVersion1_0
	case SpecVersion1_1.String():
		*sv = SpecVersion1_1
	case SpecVersion1_2.String():
		*sv = SpecVersion1_2
	case SpecVersion1_3.String():
		*sv = SpecVersion1_3
	case SpecVersion1_4.String():
		*sv = SpecVersion1_4
	}

	return nil
}
