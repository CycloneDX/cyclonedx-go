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

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	bom := NewBOM()
	bom.SerialNumber = uuid.MustParse("50b69bf2-fd4f-400e-9522-43badebb14ca").URN()
	bom.Version = 6

	t.Run("Component", func(t *testing.T) {
		c := Component{BOMRef: "ref"}

		link, err := NewBOMLink(bom, &c)
		require.NoError(t, err)
		require.Equal(t, "50b69bf2-fd4f-400e-9522-43badebb14ca", link.SerialNumber.String())
		require.Equal(t, 6, link.Version)
		require.Equal(t, "ref", link.Reference)
	})

	t.Run("Service", func(t *testing.T) {
		s := Service{BOMRef: "ref"}

		link, err := NewBOMLink(bom, &s)
		require.NoError(t, err)
		require.Equal(t, "50b69bf2-fd4f-400e-9522-43badebb14ca", link.SerialNumber.String())
		require.Equal(t, 6, link.Version)
		require.Equal(t, "ref", link.Reference)
	})

	t.Run("Vulnerability", func(t *testing.T) {
		v := Vulnerability{BOMRef: "ref"}

		link, err := NewBOMLink(bom, &v)
		require.NoError(t, err)
		require.Equal(t, "50b69bf2-fd4f-400e-9522-43badebb14ca", link.SerialNumber.String())
		require.Equal(t, 6, link.Version)
		require.Equal(t, "ref", link.Reference)
	})
}

func TestBOMLink_String(t *testing.T) {
	t.Run("WithReference", func(t *testing.T) {
		link := BOMLink{
			SerialNumber: uuid.MustParse("50b69bf2-fd4f-400e-9522-43badebb14ca"),
			Version:      6,
			Reference:    "r/e/f@1.2.3",
		}
		require.Equal(t, "urn:cdx:50b69bf2-fd4f-400e-9522-43badebb14ca/6#r%2Fe%2Ff%401.2.3", link.String())
	})

	t.Run("WithoutReference", func(t *testing.T) {
		link := BOMLink{
			SerialNumber: uuid.MustParse("50b69bf2-fd4f-400e-9522-43badebb14ca"),
			Version:      6,
			Reference:    "",
		}
		require.Equal(t, "urn:cdx:50b69bf2-fd4f-400e-9522-43badebb14ca/6", link.String())
	})
}

func TestParseBOMLink(t *testing.T) {
	t.Run("WithReference", func(t *testing.T) {
		link, err := ParseBOMLink("urn:cdx:50b69bf2-fd4f-400e-9522-43badebb14ca/6#r%2Fe%2Ff%401.2.3")
		require.NoError(t, err)
		require.Equal(t, uuid.MustParse("50b69bf2-fd4f-400e-9522-43badebb14ca"), link.SerialNumber)
		require.Equal(t, 6, link.Version)
		require.Equal(t, "r/e/f@1.2.3", link.Reference)
	})

	t.Run("WithoutReference", func(t *testing.T) {
		link, err := ParseBOMLink("urn:cdx:50b69bf2-fd4f-400e-9522-43badebb14ca/6")
		require.NoError(t, err)
		require.Equal(t, uuid.MustParse("50b69bf2-fd4f-400e-9522-43badebb14ca"), link.SerialNumber)
		require.Equal(t, 6, link.Version)
		require.Equal(t, "", link.Reference)
	})

	t.Run("Invalid", func(t *testing.T) {
		link, err := ParseBOMLink("urn:uuid:50b69bf2-fd4f-400e-9522-43badebb14ca")
		require.Error(t, err)
		require.Nil(t, link)
	})
}
