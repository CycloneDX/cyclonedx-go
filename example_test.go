package cyclonedx_test

import (
	"fmt"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"net/http"
	"os"
)

// This example demonstrates how to create and encode a BOM in CycloneDX format.
func Example_encode() {
	metadata := cdx.Metadata{
		// Define metadata about the main component
		// (the component which the BOM will describe)
		Component: &cdx.Component{
			BOMRef:  "pkg:golang/acme-inc/acme-app@v1.0.0",
			Type:    cdx.ComponentTypeApplication,
			Name:    "ACME Application",
			Version: "v1.0.0",
		},
		// Use properties to include an internal identifier for this BOM
		// https://cyclonedx.org/use-cases/#properties--name-value-store
		Properties: &[]cdx.Property{
			{
				Name:  "internal:bom-identifier",
				Value: "123456789",
			},
		},
	}

	// Define the components that acme-app ships with
	// https://cyclonedx.org/use-cases/#inventory
	components := []cdx.Component{
		{
			BOMRef:     "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.3.0",
			Type:       cdx.ComponentTypeLibrary,
			Author:     "CycloneDX",
			Name:       "cyclonedx-go",
			Version:    "v0.3.0",
			PackageURL: "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.3.0",
		},
	}

	// Define the dependency graph
	// https://cyclonedx.org/use-cases/#dependency-graph
	dependencies := []cdx.Dependency{
		{
			Ref: "pkg:golang/acme-inc/acme-app@v1.0.0",
			Dependencies: &[]cdx.Dependency{
				{Ref: "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.3.0"},
			},
		},
		{
			Ref: "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.3.0",
		},
	}

	// Assemble the BOM
	bom := cdx.NewBOM()
	bom.Metadata = &metadata
	bom.Components = &components
	bom.Dependencies = &dependencies

	// Encode the BOM
	encoder := cdx.NewBOMEncoder(os.Stdout, cdx.BOMFileFormatXML)
	encoder.SetPretty(true)
	if err := encoder.Encode(bom); err != nil {
		panic(err)
	}

	// Output:
	// <?xml version="1.0" encoding="UTF-8"?>
	// <bom xmlns="http://cyclonedx.org/schema/bom/1.3" version="1">
	//   <metadata>
	//     <component bom-ref="pkg:golang/acme-inc/acme-app@v1.0.0" type="application">
	//       <name>ACME Application</name>
	//       <version>v1.0.0</version>
	//     </component>
	//     <properties>
	//       <property name="internal:bom-identifier">123456789</property>
	//     </properties>
	//   </metadata>
	//   <components>
	//     <component bom-ref="pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.3.0" type="library">
	//       <author>CycloneDX</author>
	//       <name>cyclonedx-go</name>
	//       <version>v0.3.0</version>
	//       <purl>pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.3.0</purl>
	//     </component>
	//   </components>
	//   <dependencies>
	//     <dependency ref="pkg:golang/acme-inc/acme-app@v1.0.0">
	//       <dependency ref="pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.3.0"></dependency>
	//     </dependency>
	//     <dependency ref="pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.3.0"></dependency>
	//   </dependencies>
	// </bom>
}

// This example demonstrates how to decode and work with BOMs in CycloneDX format.
func Example_decode() {
	// Acquire a BOM (e.g. by downloading it)
	res, err := http.Get("https://github.com/DependencyTrack/dependency-track/releases/download/4.1.0/bom.json")
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

	// Decode the BOM
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(res.Body, cdx.BOMFileFormatJSON)
	if err = decoder.Decode(bom); err != nil {
		panic(err)
	}

	fmt.Printf("Successfully decoded BOM of %s\n", bom.Metadata.Component.PackageURL)
	fmt.Printf("- Generated: %s with %s\n", bom.Metadata.Timestamp, (*bom.Metadata.Tools)[0].Name)
	fmt.Printf("- Components: %d\n", len(*bom.Components))

	// Output:
	// Successfully decoded BOM of pkg:maven/org.dependencytrack/dependency-track@4.1.0
	// - Generated: 2021-02-09T20:40:32Z with CycloneDX Maven plugin
	// - Components: 167
}
