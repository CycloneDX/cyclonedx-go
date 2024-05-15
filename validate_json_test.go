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

package cyclonedx

import (
	"fmt"

	"github.com/xeipuuv/gojsonschema"
)

var jsonSchemaFiles = map[SpecVersion]string{
	SpecVersion1_2: "file://./schema/bom-1.2.schema.json",
	SpecVersion1_3: "file://./schema/bom-1.3.schema.json",
	SpecVersion1_4: "file://./schema/bom-1.4.schema.json",
	SpecVersion1_5: "file://./schema/bom-1.5.schema.json",
	SpecVersion1_6: "file://./schema/bom-1.6.schema.json",
}

type jsonValidator struct{}

func newJSONValidator() validator {
	return &jsonValidator{}
}

func (jv jsonValidator) Validate(bom []byte, specVersion SpecVersion) error {
	schemaFilePath, ok := jsonSchemaFiles[specVersion]
	if !ok {
		return fmt.Errorf("no json schema known for spec version %s", specVersion)
	}

	schemaLoader := gojsonschema.NewReferenceLoader(schemaFilePath)
	documentLoader := gojsonschema.NewBytesLoader(bom)

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return fmt.Errorf("failed to validate: %w", err)
	}

	if result.Valid() {
		return nil
	}

	errSummary := fmt.Sprintf("encountered %d validation errors:", len(result.Errors()))
	for _, verr := range result.Errors() {
		errSummary += fmt.Sprintf("\n  - %s", verr.String())
	}

	return fmt.Errorf(errSummary)
}
