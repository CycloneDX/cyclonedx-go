package cyclonedx

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBOMEncoder(t *testing.T) {
	assert.IsType(t, &jsonBOMEncoder{}, NewBOMEncoder(nil, BOMFileFormatJSON))
	assert.IsType(t, &xmlBOMEncoder{}, NewBOMEncoder(nil, BOMFileFormatXML))
}

func TestJsonBOMEncoder_Encode(t *testing.T) {
	// TODO: Build a BOM that includes all CycloneDX elements
	writeAndValidateBOM(t, NewBOM(), BOMFileFormatJSON)
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

func TestXmlBOMEncoder_Encode(t *testing.T) {
	// TODO: Build a BOM that includes all CycloneDX elements
	writeAndValidateBOM(t, NewBOM(), BOMFileFormatXML)
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

	assert.Equal(t, `<?xml version="1.0"?>
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

func writeAndValidateBOM(t *testing.T, bom *BOM, bomFileFormat BOMFileFormat) {
	var bomFileExtension string
	if bomFileFormat == BOMFileFormatJSON {
		bomFileExtension = "json"
	} else {
		bomFileExtension = "xml"
	}

	bomFile, err := ioutil.TempFile("", "bom.*."+bomFileExtension)
	require.NoError(t, err)
	defer os.Remove(bomFile.Name())

	require.NoError(t, NewBOMEncoder(bomFile, bomFileFormat).Encode(bom))
	bomFile.Close() // Required for CLI to be able to access the file

	cliCmd := exec.Command("cyclonedx", "validate", "--input-file", bomFile.Name(), "--fail-on-errors")
	cliOutput, err := cliCmd.CombinedOutput()
	if !assert.NoError(t, err) {
		// Provide some context when test is failing
		fmt.Printf("validation error: %s\n", string(cliOutput))
	}
}
