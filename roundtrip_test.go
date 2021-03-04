package cyclonedx

import (
	"bytes"
	"os"
	"testing"

	"github.com/bradleyjkemp/cupaloy/v2"
	"github.com/stretchr/testify/require"
)

var roundTripSnapshotter = cupaloy.NewDefaultConfig().
	WithOptions(cupaloy.SnapshotSubdirectory("./testdata/snapshots"))

func TestRoundTripJSON(t *testing.T) {
	// Read original BOM JSON
	bomFile, err := os.Open("./testdata/bom-1.2.json")
	require.NoError(t, err)
	defer bomFile.Close()

	// Decode BOM
	bom := new(BOM)
	require.NoError(t, NewBOMDecoder(bomFile, BOMFileFormatJSON).Decode(bom))

	// Encode BOM again
	buf := new(bytes.Buffer)
	encoder := NewBOMEncoder(buf, BOMFileFormatJSON)
	encoder.SetPretty(true)
	require.NoError(t, encoder.Encode(bom))

	// Compare with snapshot
	roundTripSnapshotter.SnapshotT(t, buf.String())
}

func TestRoundTripXML(t *testing.T) {
	// Read original BOM XML
	bomFile, err := os.Open("./testdata/bom-1.2.xml")
	require.NoError(t, err)
	defer bomFile.Close()

	// Decode BOM
	bom := new(BOM)
	require.NoError(t, NewBOMDecoder(bomFile, BOMFileFormatXML).Decode(bom))

	// Encode BOM again
	buf := new(bytes.Buffer)
	encoder := NewBOMEncoder(buf, BOMFileFormatXML)
	encoder.SetPretty(true)
	require.NoError(t, encoder.Encode(bom))

	// Compare with snapshot
	roundTripSnapshotter.SnapshotT(t, buf.String())
}
