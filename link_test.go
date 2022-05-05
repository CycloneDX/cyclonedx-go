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
	"github.com/stretchr/testify/require"
)

func TestNewBOMLink(t *testing.T) {
	t.Run("InvalidSerial", func(t *testing.T) {
		for _, input := range []string{
			"",
			"50b69bf2",
			"50b69bf2-fd4f",
			"50b69bf2-fd4f-400e-9522",
			"50b69bf2-fd4f-400e-9522-43badebb14ca",
			"uuid:50b69bf2-fd4f-400e-9522-43badebb14ca",
			"urn:50b69bf2-fd4f-400e-9522-43badebb14ca",
		} {
			link, err := NewBOMLink(input, 1, nil)
			require.Error(t, err)
			require.Zero(t, link)
		}
	})

	t.Run("InvalidVersion", func(t *testing.T) {
		for _, input := range []int{0, -1} {
			link, err := NewBOMLink("urn:uuid:50b69bf2-fd4f-400e-9522-43badebb14ca", input, nil)
			require.Error(t, err)
			require.Zero(t, link)
		}
	})

	t.Run("ElementWithRef", func(t *testing.T) {
		tests := map[string]interface{}{
			"Component":        Component{BOMRef: "ref"},
			"ComponentPtr":     &Component{BOMRef: "ref"},
			"Service":          Service{BOMRef: "ref"},
			"ServicePtr":       &Service{BOMRef: "ref"},
			"Vulnerability":    Vulnerability{BOMRef: "ref"},
			"VulnerabilityPtr": &Vulnerability{BOMRef: "ref"},
		}

		for name, input := range tests {
			t.Run(name, func(t *testing.T) {
				link, err := NewBOMLink("urn:uuid:50b69bf2-fd4f-400e-9522-43badebb14ca", 6, input)
				require.NoError(t, err)
				require.Equal(t, "urn:uuid:50b69bf2-fd4f-400e-9522-43badebb14ca", link.SerialNumber())
				require.Equal(t, 6, link.Version())
				require.Equal(t, "ref", link.Reference())
			})
		}
	})

	t.Run("ElementWithoutRef", func(t *testing.T) {
		link, err := NewBOMLink("urn:uuid:50b69bf2-fd4f-400e-9522-43badebb14ca", 6, Component{})
		require.Error(t, err)
		require.Zero(t, link)
	})

	t.Run("NonLinkableElement", func(t *testing.T) {
		link, err := NewBOMLink("urn:uuid:50b69bf2-fd4f-400e-9522-43badebb14ca", 1, OrganizationalEntity{})
		require.Error(t, err)
		require.Zero(t, link)
	})
}

func TestBOMLink_String(t *testing.T) {
	tests := map[string]struct {
		input string
		want  string
	}{
		"WithRef":    {input: "r/e/f@1.2.3", want: "urn:cdx:50b69bf2-fd4f-400e-9522-43badebb14ca/6#r%2Fe%2Ff%401.2.3"},
		"WithoutRef": {input: "", want: "urn:cdx:50b69bf2-fd4f-400e-9522-43badebb14ca/6"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			link := BOMLink{
				serialNumber: "urn:uuid:50b69bf2-fd4f-400e-9522-43badebb14ca",
				version:      6,
				reference:    tc.input,
			}
			require.Equal(t, tc.want, link.String())
		})
	}
}

func TestIsBOMLink(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		for _, input := range []string{
			"urn:cdx:ca0265ad-5bb3-46f2-8523-af52a7efc40b/1",
			"urn:cdx:ca0265ad-5bb3-46f2-8523-af52a7efc40b/111",
			"urn:cdx:ca0265ad-5bb3-46f2-8523-af52a7efc40b/1#ref",
			"urn:cdx:ca0265ad-5bb3-46f2-8523-af52a7efc40b/1#r%2Fe%2Ff",
		} {
			assert.True(t, IsBOMLink(input))
		}
	})

	t.Run("Invalid", func(t *testing.T) {
		for _, input := range []string{
			"urn",
			"urn:cdx",
			"urn:cdx:foo-bar",
			"urn:cdx:ca0265ad-5bb3-46f2-8523-af52a7efc40b",
			"urn:cdx:ca0265ad-5bb3-46f2-8523-af52a7efc40b#ref",
			"urn:cdx:ca0265ad-5bb3-46f2-8523-af52a7efc40b/#ref",
			"urn:cdx:ca0265ad-5bb3-46f2-8523-af52a7efc40b/1#",
			"urn:cdx:ca0265ad-5bb3-46f2-8523-af52a7efc40b/0",
		} {
			assert.False(t, IsBOMLink(input), input)
		}
	})
}

func TestParseBOMLink(t *testing.T) {
	t.Run("WithReference", func(t *testing.T) {
		link, err := ParseBOMLink("urn:cdx:50b69bf2-fd4f-400e-9522-43badebb14ca/6#r%2Fe%2Ff%401.2.3")
		require.NoError(t, err)
		require.Equal(t, "urn:uuid:50b69bf2-fd4f-400e-9522-43badebb14ca", link.serialNumber)
		require.Equal(t, 6, link.version)
		require.Equal(t, "r/e/f@1.2.3", link.reference)
	})

	t.Run("WithoutReference", func(t *testing.T) {
		link, err := ParseBOMLink("urn:cdx:50b69bf2-fd4f-400e-9522-43badebb14ca/6")
		require.NoError(t, err)
		require.Equal(t, "urn:uuid:50b69bf2-fd4f-400e-9522-43badebb14ca", link.serialNumber)
		require.Equal(t, 6, link.version)
		require.Equal(t, "", link.reference)
	})

	t.Run("Invalid", func(t *testing.T) {
		tests := map[string]string{
			"UUIDURN":     "urn:uuid:50b69bf2-fd4f-400e-9522-43badebb14ca",
			"InvalidUUID": "urn:cdx:foobar",
			"NoVersion":   "urn:cdx:50b69bf2-fd4f-400e-9522-43badebb14ca",
			"ZeroVersion": "urn:cdx:50b69bf2-fd4f-400e-9522-43badebb14ca/0",
		}

		for name, input := range tests {
			t.Run(name, func(t *testing.T) {
				link, err := ParseBOMLink(input)
				require.Error(t, err)
				require.Zero(t, link)
			})
		}
	})
}
