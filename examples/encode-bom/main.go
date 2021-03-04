package main

import (
	"os"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func main() {
	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{
		Timestamp: time.Now().Format(time.RFC3339),
		Component: &cdx.Component{
			BOMRef:  "pkg:golang/acme-inc/acme-app@1.0.0",
			Type:    cdx.ComponentTypeApplication,
			Name:    "ACME Application",
			Version: "1.0.0",
		},
	}
	bom.Components = &[]cdx.Component{
		{
			BOMRef:      "pkg:golang/github.com/CycloneDX/cyclonedx-go@0.1.0",
			Type:        cdx.ComponentTypeLibrary,
			Author:      "CycloneDX",
			Name:        "cyclonedx-go",
			Version:     "0.1.0",
			Description: "Go library to consume and produce CycloneDX Software Bill of Materials (SBOM)",
			PackageURL:  "pkg:golang/github.com/CycloneDX/cyclonedx-go@0.1.0",
			ExternalReferences: &[]cdx.ExternalReference{
				{
					Type: cdx.ERTypeIssueTracker,
					URL:  "https://github.com/CycloneDX/cyclonedx-go/issues",
				},
				{
					Type: cdx.ERTypeWebsite,
					URL:  "https://cyclonedx.org",
				},
			},
		},
	}
	bom.Dependencies = &[]cdx.Dependency{
		{
			Ref: "pkg:golang/acme-inc/acme-app@1.0.0",
			Dependencies: &[]cdx.Dependency{
				{Ref: "pkg:golang/github.com/CycloneDX/cyclonedx-go@0.1.0"},
			},
		},
	}

	encoder := cdx.NewBOMEncoder(os.Stdout, cdx.BOMFileFormatXML)
	encoder.SetPretty(true)

	if err := encoder.Encode(bom); err != nil {
		panic(err)
	}
}
