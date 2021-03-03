package cyclonedx

import (
	"encoding/json"
	"encoding/xml"
	"io"
)

type BOMDecoder interface {
	Decode(bom *BOM) error
}

func NewBOMDecoder(reader io.Reader, format BOMFileFormat) BOMDecoder {
	if format == BOMFileFormatJSON {
		return &jsonBOMDecoder{reader: reader}
	}
	return &xmlBOMDecoder{reader: reader}
}

type jsonBOMDecoder struct {
	reader io.Reader
}

func (j jsonBOMDecoder) Decode(bom *BOM) error {
	return json.NewDecoder(j.reader).Decode(bom)
}

type xmlBOMDecoder struct {
	reader io.Reader
}

func (x xmlBOMDecoder) Decode(bom *BOM) error {
	return xml.NewDecoder(x.reader).Decode(bom)
}
