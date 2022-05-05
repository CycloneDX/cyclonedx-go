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

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func ExampleNewBOMLink() {
	bom := cdx.NewBOM()
	bom.SerialNumber = "urn:uuid:bd064d10-4238-4a2e-9517-216f79ed77ad"
	bom.Version = 2
	bom.Metadata = &cdx.Metadata{
		Component: &cdx.Component{
			BOMRef:     "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.5.0?type=module",
			Type:       cdx.ComponentTypeLibrary,
			Name:       "github.com/CycloneDX/cyclonedx-go",
			Version:    "v0.5.0",
			PackageURL: "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.5.0?type=module",
		},
	}

	link, _ := cdx.NewBOMLink(bom.SerialNumber, bom.Version, nil)
	deepLink, _ := cdx.NewBOMLink(bom.SerialNumber, bom.Version, bom.Metadata.Component)

	fmt.Println(link.String())
	fmt.Println(deepLink.String())

	// Output:
	// urn:cdx:bd064d10-4238-4a2e-9517-216f79ed77ad/2
	// urn:cdx:bd064d10-4238-4a2e-9517-216f79ed77ad/2#pkg%3Agolang%2Fgithub.com%2FCycloneDX%2Fcyclonedx-go%40v0.5.0%3Ftype%3Dmodule
}
