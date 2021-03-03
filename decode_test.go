package cyclonedx

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// TODO: Have both bom-1.2.json and bom-1.2.xml contain the same data so we can reuse assertions

func TestJsonBOMDecoder_Decode(t *testing.T) {
	bomFile, err := os.Open("./testdata/bom-1.2.json")
	require.NoError(t, err)
	defer bomFile.Close()

	// TODO: Assert fields
}

func TestXmlBOMDecoder_Decode(t *testing.T) {
	bomFile, err := os.Open("./testdata/bom-1.2.xml")
	require.NoError(t, err)
	defer bomFile.Close()

	bom := new(BOM)
	require.NoError(t, NewBOMDecoder(bomFile, BOMFileFormatXML).Decode(bom))

	// TODO: Assert fields
}
