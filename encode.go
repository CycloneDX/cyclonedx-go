package cyclonedx

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
)

type BOMEncoder interface {
	Encode(*BOM) error
	SetPretty(bool)
}

func NewBOMEncoder(writer io.Writer, format BOMFileFormat) BOMEncoder {
	if format == BOMFileFormatJSON {
		return &jsonBOMEncoder{writer: writer}
	}
	return &xmlBOMEncoder{writer: writer}
}

type jsonBOMEncoder struct {
	writer io.Writer
	pretty bool
}

func (j jsonBOMEncoder) Encode(bom *BOM) error {
	encoder := json.NewEncoder(j.writer)
	if j.pretty {
		encoder.SetIndent("", "    ")
	}
	return encoder.Encode(bom)
}

func (j *jsonBOMEncoder) SetPretty(pretty bool) {
	j.pretty = pretty
}

type xmlBOMEncoder struct {
	writer io.Writer
	pretty bool
}

func (x xmlBOMEncoder) Encode(bom *BOM) error {
	if _, err := fmt.Fprintf(x.writer, "<?xml version=\"1.0\"?>\n"); err != nil {
		return err
	}

	encoder := xml.NewEncoder(x.writer)
	if x.pretty {
		encoder.Indent("", "    ")
	}
	return encoder.Encode(bom)
}

func (x *xmlBOMEncoder) SetPretty(pretty bool) {
	x.pretty = pretty
}
