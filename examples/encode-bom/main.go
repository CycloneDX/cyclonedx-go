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
			BOMRef:  "pkg:golang/acme-inc/acme-app@v1.0.0",
			Type:    cdx.ComponentTypeApplication,
			Name:    "ACME Application",
			Version: "v1.0.0",
		},
		Properties: &[]cdx.Property{
			{
				Name:  "internal-bom-identifier",
				Value: "123456789",
			},
		},
	}
	bom.Components = &[]cdx.Component{
		{
			BOMRef:      "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.3.0",
			Type:        cdx.ComponentTypeLibrary,
			Author:      "CycloneDX",
			Name:        "cyclonedx-go",
			Version:     "v0.3.0",
			Description: "Go library to consume and produce CycloneDX Software Bill of Materials (SBOM)",
			PackageURL:  "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.3.0",
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
			Ref: "pkg:golang/acme-inc/acme-app@v1.0.0",
			Dependencies: &[]cdx.Dependency{
				{Ref: "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.3.0"},
			},
		},
		{
			Ref: "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.3.0",
		},
	}
	bom.Compositions = &[]cdx.Composition{
		{
			Aggregate: cdx.CompositionAggregateComplete,
			Assemblies: &[]cdx.BOMReference{
				"pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.3.0",
			},
			Dependencies: &[]cdx.BOMReference{
				"pkg:golang/acme-inc/acme-app@v1.0.0",
			},
		},
	}

	encoder := cdx.NewBOMEncoder(os.Stdout, cdx.BOMFileFormatXML)
	encoder.SetPretty(true)

	if err := encoder.Encode(bom); err != nil {
		panic(err)
	}
}
