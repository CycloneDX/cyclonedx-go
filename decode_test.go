package cyclonedx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewBOMDecoder(t *testing.T) {
	assert.IsType(t, &jsonBOMDecoder{}, NewBOMDecoder(nil, BOMFileFormatJSON))
	assert.IsType(t, &xmlBOMDecoder{}, NewBOMDecoder(nil, BOMFileFormatXML))
}
