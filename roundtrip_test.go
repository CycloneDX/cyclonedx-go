package cyclonedx

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"

	"github.com/bradleyjkemp/cupaloy/v2"
	"github.com/stretchr/testify/assert"
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

	tempFile, err := ioutil.TempFile("", "bom.*.json")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	encoder := NewBOMEncoder(io.MultiWriter(buf, tempFile), BOMFileFormatJSON)
	encoder.SetPretty(true)
	require.NoError(t, encoder.Encode(bom))
	tempFile.Close() // Required for CLI to be able to access the file

	// Sanity checks: BOM has to be valid
	assertValidBOM(t, tempFile.Name())

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

	tempFile, err := ioutil.TempFile("", "bom.*.xml")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	encoder := NewBOMEncoder(io.MultiWriter(buf, tempFile), BOMFileFormatXML)
	encoder.SetPretty(true)
	require.NoError(t, encoder.Encode(bom))
	tempFile.Close() // Required for CLI to be able to access the file

	// Sanity check: BOM has to be valid
	assertValidBOM(t, tempFile.Name())

	// Compare with snapshot
	roundTripSnapshotter.SnapshotT(t, buf.String())
}

func assertValidBOM(t *testing.T, bomFilePath string) {
	valCmd := exec.Command("cyclonedx", "validate", "--input-file", bomFilePath, "--fail-on-errors")
	valOut, err := valCmd.CombinedOutput()
	if !assert.NoError(t, err) {
		// Provide some context when test is failing
		fmt.Printf("validation error: %s\n", string(valOut))
	}
}
