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
// Copyright (c) Niklas Düster. All Rights Reserved.

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
