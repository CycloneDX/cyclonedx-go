package main

import (
	"fmt"
	"net/http"

	"github.com/CycloneDX/cyclonedx-go"
)

func main() {
	res, err := http.Get("https://github.com/DependencyTrack/dependency-track/releases/download/4.1.0/bom.json")
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

	bom := new(cyclonedx.BOM)
	decoder := cyclonedx.NewBOMDecoder(res.Body, cyclonedx.BOMFileFormatJSON)
	if err = decoder.Decode(bom); err != nil {
		panic(err)
	}

	fmt.Printf("Successfully decoded BOM of %s\n", bom.Metadata.Component.PackageURL)
	fmt.Printf("- Generated: %s with %s\n", bom.Metadata.Timestamp, (*bom.Metadata.Tools)[0].Name)
	fmt.Printf("- Components: %d\n", len(*bom.Components))
}
