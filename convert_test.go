package cyclonedx

import (
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
				Identity:    &EvidenceIdentity{},
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
		var val int = 42

		comp := Component{
			Evidence: &Evidence{
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
