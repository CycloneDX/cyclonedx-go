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

	"github.com/mitchellh/copystructure"
)

// Copy returns a deep copy of the BOM.
func (b *BOM) Copy() (*BOM, error) {
	copyRes, err := copystructure.Copy(b)
	if err != nil {
		return nil, err
	}

	bomCopy, ok := copyRes.(*BOM)
	if !ok {
		return nil, fmt.Errorf("invalid type")
	}

	return bomCopy, nil
}
