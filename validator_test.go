package cyclonedx_test

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
	"net/http"
	"strings"
	"testing"
)

func TestValidator(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		res, err := http.Get("https://github.com/DependencyTrack/dependency-track/releases/download/4.1.0/bom.json")
		require.NoError(t, err)
		defer res.Body.Close()

		// Decode the BOM
		bom := new(cdx.BOM)
		decoder := cdx.NewBOMDecoder(res.Body, cdx.BOMFileFormatJSON)
		err = decoder.Decode(bom)
		require.NoError(t, err)

		validator := cdx.NewJSONSchemaValidator()
		err, errors := validator.Validate(*bom)
		require.NoError(t, err)
		require.Empty(t, errors)
	})

	t.Run("BOM invalid enum value", func(t *testing.T) {
		json := `{
		  "bomFormat": "cdx",
		  "specVersion": "1.5",
		  "serialNumber": "urn:uuid:a64492bd-dc8c-4a32-9e9f-289d81fbcb86",
		  "version": 1}
		`

		// Decode the BOM
		bom := new(cdx.BOM)
		decoder := cdx.NewBOMDecoder(strings.NewReader(json), cdx.BOMFileFormatJSON)
		err := decoder.Decode(bom)
		require.NoError(t, err)

		validator := cdx.NewJSONSchemaValidator()
		err, errors := validator.Validate(*bom)
		require.NoError(t, err)
		require.NotEmpty(t, errors)
		require.Len(t, errors, 1)
	})

	t.Run("BOM missing specVersion errors early", func(t *testing.T) {
		json := `{
		  "serialNumber": "urn:uuid:a64492bd-dc8c-4a32-9e9f-289d81fbcb86"}
		`

		// Decode the BOM
		bom := new(cdx.BOM)
		decoder := cdx.NewBOMDecoder(strings.NewReader(json), cdx.BOMFileFormatJSON)
		err := decoder.Decode(bom)
		require.NoError(t, err)

		validator := cdx.NewJSONSchemaValidator()
		err, errors := validator.Validate(*bom)
		require.Error(t, err)
		require.Empty(t, errors)
	})

	t.Run("BOM missing required properties", func(t *testing.T) {
		json := `{
		  "serialNumber": "urn:uuid:a64492bd-dc8c-4a32-9e9f-289d81fbcb86",
		  "specVersion": "1.5"}
		`

		// Decode the BOM
		bom := new(cdx.BOM)
		decoder := cdx.NewBOMDecoder(strings.NewReader(json), cdx.BOMFileFormatJSON)
		err := decoder.Decode(bom)
		require.NoError(t, err)

		validator := cdx.NewJSONSchemaValidator()
		err, errors := validator.Validate(*bom)
		require.NoError(t, err)
		require.NotEmpty(t, errors)
		require.Len(t, errors, 2)
		for _, e := range errors {
			require.ErrorIs(t, e, cdx.ErrRequiredFieldMissing)
		}
	})

	t.Run("BOM unsupported specVersion", func(t *testing.T) {
		json := `{
		  "bomFormat": "CycloneDX",
		  "specVersion": "1.0",
		  "serialNumber": "urn:uuid:a64492bd-dc8c-4a32-9e9f-289d81fbcb86",
		  "version": 1}
		`

		// Decode the BOM
		bom := new(cdx.BOM)
		decoder := cdx.NewBOMDecoder(strings.NewReader(json), cdx.BOMFileFormatJSON)
		err := decoder.Decode(bom)
		require.NoError(t, err)

		validator := cdx.NewJSONSchemaValidator()
		err, errors := validator.Validate(*bom)
		require.Error(t, err)
		require.Empty(t, errors)
	})
}
