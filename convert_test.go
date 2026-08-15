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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_componentConverter_convertEvidence(t *testing.T) {
	t.Run("spec 1.2 and lower", func(t *testing.T) {
		convert := componentConverter(SpecVersion1_2)

		comp := Component{
			Evidence: &Evidence{},
		}

		convert(&comp)

		assert.Nil(t, comp.Evidence)
	})

	t.Run("spec 1.4 and lower", func(t *testing.T) {
		convert := componentConverter(SpecVersion1_4)

		comp := Component{
			Evidence: &Evidence{
				Identity:    &EvidenceIdentityChoice{Identities: &[]EvidenceIdentity{}},
				Occurrences: &[]EvidenceOccurrence{},
				Callstack:   &Callstack{},
				Copyright:   &[]Copyright{{Text: "foo"}},
			},
		}

		convert(&comp)

		assert.Nil(t, comp.Evidence.Identity)
		assert.Nil(t, comp.Evidence.Occurrences)
		assert.Nil(t, comp.Evidence.Callstack)
		assert.NotNil(t, comp.Evidence.Copyright)
	})

	t.Run("spec 1.5 and lower", func(t *testing.T) {
		convert := componentConverter(SpecVersion1_5)
		var val = 42

		comp := Component{
			Evidence: &Evidence{
				Identity: &EvidenceIdentityChoice{Identities: &[]EvidenceIdentity{
					{
						Field:          EvidenceIdentityFieldTypePURL,
						ConcludedValue: "pkg:generic/acme@1.0.0",
					},
					{
						Field: EvidenceIdentityFieldTypeName,
					},
				}},
				Occurrences: &[]EvidenceOccurrence{
					{
						BOMRef:            "foo",
						Location:          "bar",
						Line:              &val,
						Offset:            &val,
						Symbol:            "asdf",
						AdditionalContext: "quux",
					},
				},
			},
		}

		convert(&comp)

		// 1.5 defines identity as a single object, so the array must collapse to
		// the first entry stored as a single Identity (not Identities); otherwise
		// the encoded document fails the 1.5 schema (identity must be an object).
		require.NotNil(t, comp.Evidence.Identity.Identity)
		require.Nil(t, comp.Evidence.Identity.Identities)
		assert.Equal(t, EvidenceIdentityFieldTypePURL, comp.Evidence.Identity.Identity.Field)
		// concludedValue was introduced in 1.6 and must be dropped.
		assert.Zero(t, comp.Evidence.Identity.Identity.ConcludedValue)
		require.Len(t, *comp.Evidence.Occurrences, 1)
		occ := (*comp.Evidence.Occurrences)[0]
		assert.Nil(t, occ.Line)
		assert.Nil(t, occ.Offset)
		assert.Zero(t, occ.Symbol)
		assert.Zero(t, occ.AdditionalContext)
	})
}

func Test_convertLicenses(t *testing.T) {
	t.Run("spec 1.5 and lower", func(t *testing.T) {
		bom := NewBOM()
		bom.Metadata = &Metadata{
			Licenses: &Licenses{
				{License: &License{Name: "Apache License 2.0", Acknowledgement: LicenseAcknowledgementDeclared}},
			},
		}
		bom.Components = &[]Component{
			{
				Name: "foo",
				Licenses: &Licenses{
					{License: &License{Name: "Apache License 2.0", Acknowledgement: LicenseAcknowledgementConcluded}},
				},
			},
		}

		bom.convert(SpecVersion1_5)

		assert.Zero(t, (*bom.Metadata.Licenses)[0].License.Acknowledgement)
		assert.Zero(t, (*(*bom.Components)[0].Licenses)[0].License.Acknowledgement)
	})
}

func Test_convertTools_OrganizationalEntity(t *testing.T) {
	t.Run("spec 1.5 and lower", func(t *testing.T) {
		orgStub := func() *OrganizationalEntity {
			t.Helper()
			return &OrganizationalEntity{
				Name:    "Acme Corp",
				Address: &PostalAddress{},
			}
		}

		bom := NewBOM()
		bom.Metadata = &Metadata{
			Manufacture: orgStub(),
			Supplier:    orgStub(),
			Tools: &ToolsChoice{
				Services: &[]Service{{Provider: orgStub()}},
			},
			Licenses: &Licenses{
				{
					License: &License{
						Licensing: &Licensing{
							Licensor:  &OrganizationalEntityOrContact{Organization: orgStub()},
							Licensee:  &OrganizationalEntityOrContact{Organization: orgStub()},
							Purchaser: &OrganizationalEntityOrContact{Organization: orgStub()},
						},
					},
				},
			},
		}
		bom.Vulnerabilities = &[]Vulnerability{
			{
				ID: "some-vuln",
				Credits: &Credits{
					Organizations: &[]OrganizationalEntity{*orgStub()},
				},
			},
		}
		bom.Annotations = &[]Annotation{
			{
				Annotator: &Annotator{
					Organization: orgStub(),
					Service:      &Service{Provider: orgStub()},
				},
			},
		}

		bom.convert(SpecVersion1_5)

		assert.Nil(t, bom.Metadata.Manufacture.Address)
		assert.Nil(t, bom.Metadata.Supplier.Address)
		assert.Nil(t, (*bom.Metadata.Tools.Services)[0].Provider.Address)

		assert.Nil(t, (*bom.Metadata.Licenses)[0].License.Licensing.Licensor.Organization.Address)
		assert.Nil(t, (*bom.Metadata.Licenses)[0].License.Licensing.Licensee.Organization.Address)
		assert.Nil(t, (*bom.Metadata.Licenses)[0].License.Licensing.Purchaser.Organization.Address)

		assert.Nil(t, (*(*bom.Vulnerabilities)[0].Credits.Organizations)[0].Address)

		assert.Nil(t, (*bom.Annotations)[0].Annotator.Organization.Address)
		assert.Nil(t, (*bom.Annotations)[0].Annotator.Service.Provider.Address)
	})
}

func Test_convertModelCard(t *testing.T) {
	t.Run("spec 1.5 and lower", func(t *testing.T) {
		bom := NewBOM()
		bom.Metadata = &Metadata{
			Component: &Component{
				ModelCard: &MLModelCard{
					Considerations: &MLModelCardConsiderations{
						EnvironmentalConsiderations: &MLModelCardEnvironmentalConsiderations{},
					},
				},
			},
		}

		bom.convert(SpecVersion1_5)

		assert.Nil(t, bom.Metadata.Component.ModelCard.Considerations.EnvironmentalConsiderations)
	})
}

func Test_convertManufacturer(t *testing.T) {
	t.Run("spec 1.5 and lower", func(t *testing.T) {
		bom := NewBOM()
		bom.Metadata = &Metadata{
			Manufacturer: &OrganizationalEntity{
				Name: "Acme, Inc.",
			},
		}
		bom.Components = &[]Component{
			{
				Name: "foo",
				Manufacturer: &OrganizationalEntity{
					Name: "Acme, Inc.",
				},
			},
		}

		bom.convert(SpecVersion1_5)

		assert.Nil(t, bom.Metadata.Manufacturer)
		assert.Nil(t, (*bom.Components)[0].Manufacturer)
	})
}

func Test_convertAuthors(t *testing.T) {
	t.Run("spec 1.5 and lower", func(t *testing.T) {
		bom := NewBOM()
		bom.Components = &[]Component{
			{
				Name: "foo",
				Authors: &[]OrganizationalContact{
					{
						Name: "Acme Professional Services",
					},
				},
			},
		}

		bom.convert(SpecVersion1_5)

		assert.Nil(t, (*bom.Components)[0].Authors)
	})
}

func Test_convertTrustZone(t *testing.T) {
	t.Run("spec 1.4 and lower", func(t *testing.T) {
		bom := NewBOM()
		bom.Services = &[]Service{
			{
				Name:      "Payment API",
				TrustZone: "trusted",
			},
		}

		bom.convert(SpecVersion1_4)

		assert.Empty(t, (*bom.Services)[0].TrustZone)
	})

	t.Run("spec 1.5 and higher", func(t *testing.T) {
		bom := NewBOM()
		bom.Services = &[]Service{
			{
				Name:      "Payment API",
				TrustZone: "trusted",
			},
		}
		bom.convert(SpecVersion1_5)
		assert.Equal(t, "trusted", (*bom.Services)[0].TrustZone)
	})
}

func Test_convertTags(t *testing.T) {
	t.Run("spec 1.5 and lower", func(t *testing.T) {
		bom := NewBOM()
		bom.Metadata = &Metadata{
			Component: &Component{
				Name: "test",
				Tags: &[]string{"tag1", "tag2"},
			},
		}
		bom.Components = &[]Component{
			{
				Name: "foo",
				Tags: &[]string{"tag3", "tag4"},
			},
		}

		bom.convert(SpecVersion1_5)

		assert.Nil(t, bom.Metadata.Component.Tags)
		assert.Nil(t, (*bom.Components)[0].Tags)
	})
}

func Test_convert_stripsFieldsNewerThanTargetSpec(t *testing.T) {
	// Downgrading a BOM must not leave behind fields that were only introduced
	// in a later spec version - the resulting document has to validate against
	// the target version's schema. These cases each reproduce a field that was
	// carried over unchanged and rejected by the older schema.

	decode := func(t *testing.T, path string) BOM {
		f, err := os.Open(path)
		require.NoError(t, err)
		defer f.Close()
		var bom BOM
		require.NoError(t, NewBOMDecoder(f, BOMFileFormatJSON).Decode(&bom))
		return bom
	}

	encodeVersion := func(t *testing.T, bom *BOM, version SpecVersion) []byte {
		var buf bytes.Buffer
		require.NoError(t, NewBOMEncoder(&buf, BOMFileFormatJSON).EncodeVersion(bom, version))
		return buf.Bytes()
	}

	t.Run("cryptoProperties removed below 1.6", func(t *testing.T) {
		bom := decode(t, "./testdata/valid-cryptographic-asset.json")
		out := encodeVersion(t, &bom, SpecVersion1_5)
		assertValidBOM(t, out, BOMFileFormatJSON, SpecVersion1_5)

		bom = decode(t, "./testdata/valid-cryptographic-asset.json")
		bom.convert(SpecVersion1_5)
		for _, c := range *bom.Components {
			assert.Nil(t, c.CryptoProperties)
		}
	})

	t.Run("composition bom-ref and vulnerabilities removed below 1.5", func(t *testing.T) {
		bom := decode(t, "./testdata/valid-compositions.json")
		out := encodeVersion(t, &bom, SpecVersion1_4)
		assertValidBOM(t, out, BOMFileFormatJSON, SpecVersion1_4)

		bom = decode(t, "./testdata/valid-compositions.json")
		bom.convert(SpecVersion1_4)
		for _, comp := range *bom.Compositions {
			assert.Empty(t, comp.BOMRef)
			assert.Nil(t, comp.Vulnerabilities)
		}
	})

	t.Run("vulnerability analysis firstIssued and lastUpdated removed below 1.5", func(t *testing.T) {
		bom := decode(t, "./testdata/valid-vulnerability.json")
		out := encodeVersion(t, &bom, SpecVersion1_4)
		assertValidBOM(t, out, BOMFileFormatJSON, SpecVersion1_4)

		bom = decode(t, "./testdata/valid-vulnerability.json")
		bom.convert(SpecVersion1_4)
		for _, vuln := range *bom.Vulnerabilities {
			if vuln.Analysis != nil {
				assert.Empty(t, vuln.Analysis.FirstIssued)
				assert.Empty(t, vuln.Analysis.LastUpdated)
			}
		}
	})
}
