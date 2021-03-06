package cyclonedx

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBOMEncoder(t *testing.T) {
	assert.IsType(t, &jsonBOMEncoder{}, NewBOMEncoder(nil, BOMFileFormatJSON))
	assert.IsType(t, &xmlBOMEncoder{}, NewBOMEncoder(nil, BOMFileFormatXML))
}

func TestJsonBOMEncoder_SetPretty(t *testing.T) {
	buf := new(bytes.Buffer)
	encoder := NewBOMEncoder(buf, BOMFileFormatJSON)
	encoder.SetPretty(true)

	bom := NewBOM()
	bom.Metadata = &Metadata{
		Authors: &[]OrganizationalContact{
			{
				Name: "authorName",
			},
		},
	}

	require.NoError(t, encoder.Encode(bom))

	assert.Equal(t, `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.2",
  "version": 1,
  "metadata": {
    "authors": [
      {
        "name": "authorName"
      }
    ]
  }
}
`, buf.String())
}

func TestXmlBOMEncoder_SetPretty(t *testing.T) {
	buf := new(bytes.Buffer)
	encoder := NewBOMEncoder(buf, BOMFileFormatXML)
	encoder.SetPretty(true)

	bom := NewBOM()
	bom.Metadata = &Metadata{
		Authors: &[]OrganizationalContact{
			{
				Name: "authorName",
			},
		},
	}

	require.NoError(t, encoder.Encode(bom))

	assert.Equal(t, `<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.2" version="1">
  <metadata>
    <authors>
      <author>
        <name>authorName</name>
      </author>
    </authors>
  </metadata>
</bom>`, buf.String())
}
