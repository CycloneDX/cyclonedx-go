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

	"github.com/stretchr/testify/require"
)

func TestEnvironmentVariableChoice_MarshalJSON(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		choice := EnvironmentVariableChoice{}
		jsonBytes, err := json.Marshal(choice)
		require.NoError(t, err)
		require.Equal(t, "{}", string(jsonBytes))
	})

	t.Run("WithProperty", func(t *testing.T) {
		choice := EnvironmentVariableChoice{
			Property: &Property{
				Name:  "foo",
				Value: "bar",
			},
		}
		jsonBytes, err := json.Marshal(choice)
		require.NoError(t, err)
		require.Equal(t, `{"name":"foo","value":"bar"}`, string(jsonBytes))
	})

	t.Run("WithValue", func(t *testing.T) {
		choice := EnvironmentVariableChoice{Value: "foo"}
		jsonBytes, err := json.Marshal(choice)
		require.NoError(t, err)
		require.Equal(t, `"foo"`, string(jsonBytes))
	})

	t.Run("WithPropertyAndValue", func(t *testing.T) {
		choice := EnvironmentVariableChoice{
			Property: &Property{
				Name:  "foo",
				Value: "bar",
			},
			Value: "baz",
		}
		jsonBytes, err := json.Marshal(choice)
		require.NoError(t, err)
		require.Equal(t, `{"name":"foo","value":"bar"}`, string(jsonBytes))
	})
}

func TestEnvironmentVariableChoice_UnmarshalJSON(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		var choice EnvironmentVariableChoice
		err := json.Unmarshal([]byte(`{}`), &choice)
		require.NoError(t, err)
		require.Equal(t, EnvironmentVariableChoice{}, choice)
	})

	t.Run("WithProperty", func(t *testing.T) {
		var choice EnvironmentVariableChoice
		err := json.Unmarshal([]byte(`{"name":"foo","value":"bar"}`), &choice)
		require.NoError(t, err)
		require.NotNil(t, choice.Property)
		require.Equal(t, "foo", choice.Property.Name)
		require.Equal(t, "bar", choice.Property.Value)
		require.Empty(t, choice.Value)
	})

	t.Run("WithValue", func(t *testing.T) {
		var choice EnvironmentVariableChoice
		err := json.Unmarshal([]byte(`"foo"`), &choice)
		require.NoError(t, err)
		require.Nil(t, choice.Property)
		require.Equal(t, "foo", choice.Value)
	})
}

func TestMLDatasetChoice_MarshalJSON(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		choice := MLDatasetChoice{}
		jsonBytes, err := json.Marshal(choice)
		require.NoError(t, err)
		require.Equal(t, "{}", string(jsonBytes))
	})

	t.Run("WithRef", func(t *testing.T) {
		choice := MLDatasetChoice{Ref: "foo"}
		jsonBytes, err := json.Marshal(choice)
		require.NoError(t, err)
		require.Equal(t, `{"ref":"foo"}`, string(jsonBytes))
	})

	t.Run("WithComponentData", func(t *testing.T) {
		choice := MLDatasetChoice{
			ComponentData: &ComponentData{
				BOMRef: "foo",
				Name:   "bar",
			},
		}
		jsonBytes, err := json.Marshal(choice)
		require.NoError(t, err)
		require.Equal(t, `{"bom-ref":"foo","name":"bar"}`, string(jsonBytes))
	})

	t.Run("WithRefAndComponentData", func(t *testing.T) {
		choice := MLDatasetChoice{
			Ref: "foo",
			ComponentData: &ComponentData{
				BOMRef: "bar",
				Name:   "baz",
			},
		}
		jsonBytes, err := json.Marshal(choice)
		require.NoError(t, err)
		require.Equal(t, `{"ref":"foo"}`, string(jsonBytes))
	})
}

func TestMLDatasetChoice_UnmarshalJSON(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		var choice MLDatasetChoice
		err := json.Unmarshal([]byte(`{}`), &choice)
		require.NoError(t, err)
		require.Equal(t, MLDatasetChoice{}, choice)
	})

	t.Run("WithRef", func(t *testing.T) {
		var choice MLDatasetChoice
		err := json.Unmarshal([]byte(`{"ref":"foo"}`), &choice)
		require.NoError(t, err)
		require.Equal(t, "foo", choice.Ref)
		require.Nil(t, choice.ComponentData)
	})

	t.Run("WithComponentData", func(t *testing.T) {
		var choice MLDatasetChoice
		err := json.Unmarshal([]byte(`{"bom-ref":"foo","name":"bar"}`), &choice)
		require.NoError(t, err)
		require.Empty(t, choice.Ref)
		require.NotNil(t, choice.ComponentData)
		require.Equal(t, "foo", choice.ComponentData.BOMRef)
		require.Equal(t, "bar", choice.ComponentData.Name)
	})

	t.Run("WithRefAndComponentData", func(t *testing.T) {
		var choice MLDatasetChoice
		err := json.Unmarshal([]byte(`{"ref":"foo","bom-ref":"bar","name":"baz"}`), &choice)
		require.NoError(t, err)
		require.Equal(t, "foo", choice.Ref)
		require.Nil(t, choice.ComponentData)
	})
}

func TestEvidence_MarshalJSON(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		evidence := Evidence{}
		jsonBytes, err := json.Marshal(evidence)
		require.NoError(t, err)
		require.Equal(t, "{}", string(jsonBytes))
	})

	t.Run("WithOccurrences", func(t *testing.T) {
		evidence := Evidence{
			Occurrences: &[]EvidenceOccurrence{
				{
					BOMRef:   "d6bf237e-4e11-4713-9f62-56d18d5e2079",
					Location: "/path/to/component",
				},
				{
					BOMRef:   "b574d5d1-e3cf-4dcd-9ba5-f3507eb1b175",
					Location: "/another/path/to/component",
				},
			},
		}
		jsonBytes, err := json.Marshal(evidence)
		require.NoError(t, err)
		require.Equal(t, `{"occurrences":[{"bom-ref":"d6bf237e-4e11-4713-9f62-56d18d5e2079","location":"/path/to/component"},{"bom-ref":"b574d5d1-e3cf-4dcd-9ba5-f3507eb1b175","location":"/another/path/to/component"}]}`, string(jsonBytes))
	})

	t.Run("WithIdentify", func(t *testing.T) {
		evidence := Evidence{
			Identity: &[]EvidenceIdentity{
				{
					Field:      EvidenceIdentityFieldTypePURL,
					Confidence: toPointer(t, float32(1)),
					Methods: &[]EvidenceIdentityMethod{
						{
							Technique:  "filename",
							Confidence: toPointer(t, float32(0.1)),
							Value:      "findbugs-project-3.0.0.jar",
						},
						{
							Technique:  "ast-fingerprint",
							Confidence: toPointer(t, float32(0.9)),
							Value:      "61e4bc08251761c3a73b606b9110a65899cb7d44f3b14c81ebc1e67c98e1d9ab",
						},
					},
					Tools: &[]BOMReference{
						"bom-ref-of-tool-that-performed-analysis",
					},
				},
			},
		}
		jsonBytes, err := json.Marshal(evidence)
		require.NoError(t, err)
		require.Equal(t, `{"Identity":[{"field":"purl","confidence":1,"methods":[{"technique":"filename","confidence":0.1,"value":"findbugs-project-3.0.0.jar"},{"technique":"ast-fingerprint","confidence":0.9,"value":"61e4bc08251761c3a73b606b9110a65899cb7d44f3b14c81ebc1e67c98e1d9ab"}],"tools":["bom-ref-of-tool-that-performed-analysis"]}]}`, string(jsonBytes))
	})
}

func TestEvidence_UnmarshalJSON(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		var evidence Evidence
		err := json.Unmarshal([]byte(`{}`), &evidence)
		require.NoError(t, err)
		require.Equal(t, Evidence{}, evidence)
	})

	t.Run("WithOccurrences", func(t *testing.T) {
		var evidence Evidence
		err := json.Unmarshal([]byte(`{
"occurrences": [
  {
	"bom-ref": "d6bf237e-4e11-4713-9f62-56d18d5e2079",
	"location": "/path/to/component"
  },
  {
	"bom-ref": "b574d5d1-e3cf-4dcd-9ba5-f3507eb1b175",
	"location": "/another/path/to/component"
  }
]}`), &evidence)
		require.NoError(t, err)
		require.Equal(t, &[]EvidenceOccurrence{
			{
				BOMRef:   "d6bf237e-4e11-4713-9f62-56d18d5e2079",
				Location: "/path/to/component",
			},
			{
				BOMRef:   "b574d5d1-e3cf-4dcd-9ba5-f3507eb1b175",
				Location: "/another/path/to/component",
			},
		}, evidence.Occurrences)
	})

	t.Run("WithIdentityAsStruct", func(t *testing.T) {
		var evidence Evidence
		err := json.Unmarshal([]byte(`{
"identity": {
  "field": "purl",
  "confidence": 1,
  "methods": [
	{
	  "technique": "filename",
	  "confidence": 0.1,
	  "value": "findbugs-project-3.0.0.jar"
	},
	{
	  "technique": "ast-fingerprint",
	  "confidence": 0.9,
	  "value": "61e4bc08251761c3a73b606b9110a65899cb7d44f3b14c81ebc1e67c98e1d9ab"
	}
  ],
  "tools": [
	"bom-ref-of-tool-that-performed-analysis"
  ]
}}`), &evidence)
		require.NoError(t, err)
		require.Equal(t, &[]EvidenceIdentity{
			{
				Field:      EvidenceIdentityFieldTypePURL,
				Confidence: toPointer(t, float32(1)),
				Methods: &[]EvidenceIdentityMethod{
					{
						Technique:  "filename",
						Confidence: toPointer(t, float32(0.1)),
						Value:      "findbugs-project-3.0.0.jar",
					},
					{
						Technique:  "ast-fingerprint",
						Confidence: toPointer(t, float32(0.9)),
						Value:      "61e4bc08251761c3a73b606b9110a65899cb7d44f3b14c81ebc1e67c98e1d9ab",
					},
				},
				Tools: &[]BOMReference{
					"bom-ref-of-tool-that-performed-analysis",
				},
			},
		}, evidence.Identity)
	})

	t.Run("WithIdentityAsArray", func(t *testing.T) {
		var evidence Evidence
		err := json.Unmarshal([]byte(`{
"identity": [
	{
		"field": "purl",
		"confidence": 1
	},
	{
		"field": "name",
		"confidence": 0.1
	}
]}`), &evidence)
		require.NoError(t, err)
		require.Equal(t, &[]EvidenceIdentity{
			{
				Field:      EvidenceIdentityFieldTypePURL,
				Confidence: toPointer(t, float32(1)),
			},
			{
				Field:      EvidenceIdentityFieldTypeName,
				Confidence: toPointer(t, float32(0.1)),
			},
		}, evidence.Identity)
	})
}
