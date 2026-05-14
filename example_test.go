// This file is part of CycloneDX Go
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an “AS IS” BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) OWASP Foundation. All Rights Reserved.

package cyclonedx_test

import (
	"fmt"
	"net/http"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
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
			Dependencies: &[]string{
				"pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.3.0",
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
	err := cdx.NewBOMEncoder(os.Stdout, cdx.BOMFileFormatXML).
		SetPretty(true).
		Encode(bom)
	if err != nil {
		panic(err)
	}

	// Output:
	// <?xml version="1.0" encoding="UTF-8"?>
	// <bom xmlns="http://cyclonedx.org/schema/bom/1.7" version="1">
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
	fmt.Printf("- Generated: %s with %s\n", bom.Metadata.Timestamp, (*bom.Metadata.Tools.Tools)[0].Name)
	fmt.Printf("- Components: %d\n", len(*bom.Components))

	// Output:
	// Successfully decoded BOM of pkg:maven/org.dependencytrack/dependency-track@4.1.0
	// - Generated: 2021-02-09T20:40:32Z with CycloneDX Maven plugin
	// - Components: 167
}
