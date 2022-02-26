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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsBOMLink(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		for _, link := range []string{
			"urn:cdx:ca0265ad-5bb3-46f2-8523-af52a7efc40b/1",
			"urn:cdx:ca0265ad-5bb3-46f2-8523-af52a7efc40b/111",
			"urn:cdx:ca0265ad-5bb3-46f2-8523-af52a7efc40b/1#ref",
			"urn:cdx:ca0265ad-5bb3-46f2-8523-af52a7efc40b/1#r%2Fe%2Ff",
		} {
			assert.True(t, IsBOMLink(link))
		}
	})

	t.Run("Invalid", func(t *testing.T) {
		for _, invalidLink := range []string{
			"urn",
			"urn:cdx",
			"urn:cdx:foo-bar",
			"urn:cdx:ca0265ad-5bb3-46f2-8523-af52a7efc40b",
			"urn:cdx:ca0265ad-5bb3-46f2-8523-af52a7efc40b#ref",
			"urn:cdx:ca0265ad-5bb3-46f2-8523-af52a7efc40b/#ref",
			"urn:cdx:ca0265ad-5bb3-46f2-8523-af52a7efc40b/1#",
		} {
			assert.False(t, IsBOMLink(invalidLink), invalidLink)
		}
	})
}

func TestNewBOMLink(t *testing.T) {
	// TODO
}

func TestParseBOMLink(t *testing.T) {
	// TODO
}
