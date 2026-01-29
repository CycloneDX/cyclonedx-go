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
		require.Equal(t, `{"identity":[{"field":"purl","confidence":1,"methods":[{"technique":"filename","confidence":0.1,"value":"findbugs-project-3.0.0.jar"},{"technique":"ast-fingerprint","confidence":0.9,"value":"61e4bc08251761c3a73b606b9110a65899cb7d44f3b14c81ebc1e67c98e1d9ab"}],"tools":["bom-ref-of-tool-that-performed-analysis"]}]}`, string(jsonBytes))
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

func TestService_TrustZone_MarshalJSON(t *testing.T) {
	t.Run("WithTrustZone", func(t *testing.T) {
		service := Service{
			Name:      "Payment API",
			TrustZone: "trusted",
		}
		jsonBytes, err := json.Marshal(service)
		require.NoError(t, err)
		require.Contains(t, string(jsonBytes), `"trustZone":"trusted"`)
		require.Contains(t, string(jsonBytes), `"name":"Payment API"`)
	})

	t.Run("WithoutTrustZone", func(t *testing.T) {
		service := Service{
			Name: "Payment API",
		}
		jsonBytes, err := json.Marshal(service)
		require.NoError(t, err)
		require.NotContains(t, string(jsonBytes), "trustZone")
		require.Contains(t, string(jsonBytes), `"name":"Payment API"`)
	})
}

func TestService_TrustZone_UnmarshalJSON(t *testing.T) {
	t.Run("WithTrustZone", func(t *testing.T) {
		var service Service
		err := json.Unmarshal([]byte(`{"name":"Payment API","trustZone":"trusted"}`), &service)
		require.NoError(t, err)
		require.Equal(t, "Payment API", service.Name)
		require.Equal(t, "trusted", service.TrustZone)
	})

	t.Run("WithoutTrustZone", func(t *testing.T) {
		var service Service
		err := json.Unmarshal([]byte(`{"name":"Payment API"}`), &service)
		require.NoError(t, err)
		require.Equal(t, "Payment API", service.Name)
		require.Empty(t, service.TrustZone)
	})
}

func TestDependency_Provides_MarshalJSON(t *testing.T) {
	t.Run("WithProvides", func(t *testing.T) {
		dependency := Dependency{
			Ref:      "crypto-library",
			Provides: &[]string{"aes128gcm", "sha256"},
		}
		jsonBytes, err := json.Marshal(dependency)
		require.NoError(t, err)
		require.Contains(t, string(jsonBytes), `"ref":"crypto-library"`)
		require.Contains(t, string(jsonBytes), `"provides":["aes128gcm","sha256"]`)
	})

	t.Run("WithProvidesAndDependsOn", func(t *testing.T) {
		dependency := Dependency{
			Ref:          "crypto-library",
			Dependencies: &[]string{"base-library"},
			Provides:     &[]string{"aes128gcm"},
		}
		jsonBytes, err := json.Marshal(dependency)
		require.NoError(t, err)
		require.Contains(t, string(jsonBytes), `"ref":"crypto-library"`)
		require.Contains(t, string(jsonBytes), `"dependsOn":["base-library"]`)
		require.Contains(t, string(jsonBytes), `"provides":["aes128gcm"]`)
	})

	t.Run("WithoutProvides", func(t *testing.T) {
		dependency := Dependency{
			Ref:          "app-component",
			Dependencies: &[]string{"library-a"},
		}
		jsonBytes, err := json.Marshal(dependency)
		require.NoError(t, err)
		require.Contains(t, string(jsonBytes), `"ref":"app-component"`)
		require.NotContains(t, string(jsonBytes), "provides")
	})
}

func TestDependency_Provides_UnmarshalJSON(t *testing.T) {
	t.Run("WithProvides", func(t *testing.T) {
		var dependency Dependency
		err := json.Unmarshal([]byte(`{"ref":"crypto-library","provides":["aes128gcm","sha256"]}`), &dependency)
		require.NoError(t, err)
		require.Equal(t, "crypto-library", dependency.Ref)
		require.NotNil(t, dependency.Provides)
		require.Equal(t, 2, len(*dependency.Provides))
		require.Equal(t, "aes128gcm", (*dependency.Provides)[0])
		require.Equal(t, "sha256", (*dependency.Provides)[1])
	})

	t.Run("WithProvidesAndDependsOn", func(t *testing.T) {
		var dependency Dependency
		err := json.Unmarshal([]byte(`{"ref":"crypto-library","dependsOn":["base-library"],"provides":["aes128gcm"]}`), &dependency)
		require.NoError(t, err)
		require.Equal(t, "crypto-library", dependency.Ref)
		require.NotNil(t, dependency.Dependencies)
		require.Equal(t, 1, len(*dependency.Dependencies))
		require.Equal(t, "base-library", (*dependency.Dependencies)[0])
		require.NotNil(t, dependency.Provides)
		require.Equal(t, 1, len(*dependency.Provides))
		require.Equal(t, "aes128gcm", (*dependency.Provides)[0])
	})

	t.Run("WithoutProvides", func(t *testing.T) {
		var dependency Dependency
		err := json.Unmarshal([]byte(`{"ref":"app-component","dependsOn":["library-a"]}`), &dependency)
		require.NoError(t, err)
		require.Equal(t, "app-component", dependency.Ref)
		require.Nil(t, dependency.Provides)
	})
}

func TestExternalReferenceType_NewValues(t *testing.T) {
	t.Run("DigitalSignature", func(t *testing.T) {
		extRef := ExternalReference{
			Type: ERTypeDigitalSignature,
			URL:  "https://example.com/signature",
		}
		jsonBytes, err := json.Marshal(extRef)
		require.NoError(t, err)
		require.Contains(t, string(jsonBytes), `"type":"digital-signature"`)
	})

	t.Run("ElectronicSignature", func(t *testing.T) {
		extRef := ExternalReference{
			Type: ERTypeElectronicSignature,
			URL:  "https://example.com/esignature",
		}
		jsonBytes, err := json.Marshal(extRef)
		require.NoError(t, err)
		require.Contains(t, string(jsonBytes), `"type":"electronic-signature"`)
	})

	t.Run("POAM", func(t *testing.T) {
		extRef := ExternalReference{
			Type: ERTypePOAM,
			URL:  "https://example.com/poam",
		}
		jsonBytes, err := json.Marshal(extRef)
		require.NoError(t, err)
		require.Contains(t, string(jsonBytes), `"type":"poam"`)
	})

	t.Run("RFC9116", func(t *testing.T) {
		extRef := ExternalReference{
			Type: ERTypeRFC9116,
			URL:  "https://example.com/security.txt",
		}
		jsonBytes, err := json.Marshal(extRef)
		require.NoError(t, err)
		require.Contains(t, string(jsonBytes), `"type":"rfc-9116"`)
	})

	t.Run("SourceDistribution", func(t *testing.T) {
		extRef := ExternalReference{
			Type: ERTypeSourceDistribution,
			URL:  "https://example.com/source.tar.gz",
		}
		jsonBytes, err := json.Marshal(extRef)
		require.NoError(t, err)
		require.Contains(t, string(jsonBytes), `"type":"source-distribution"`)
	})

	t.Run("UnmarshalNewTypes", func(t *testing.T) {
		testCases := []struct {
			name     string
			json     string
			expected ExternalReferenceType
		}{
			{"digital-signature", `{"type":"digital-signature","url":"https://example.com"}`, ERTypeDigitalSignature},
			{"electronic-signature", `{"type":"electronic-signature","url":"https://example.com"}`, ERTypeElectronicSignature},
			{"poam", `{"type":"poam","url":"https://example.com"}`, ERTypePOAM},
			{"rfc-9116", `{"type":"rfc-9116","url":"https://example.com"}`, ERTypeRFC9116},
			{"source-distribution", `{"type":"source-distribution","url":"https://example.com"}`, ERTypeSourceDistribution},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				var extRef ExternalReference
				err := json.Unmarshal([]byte(tc.json), &extRef)
				require.NoError(t, err)
				require.Equal(t, tc.expected, extRef.Type)
			})
		}
	})
}
