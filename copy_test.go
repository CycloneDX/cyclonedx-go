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
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBOM_copy(t *testing.T) {
	t.Run("preserves zero-valued pointer fields", func(t *testing.T) {
		zero := 0.0

		bom := BOM{
			Vulnerabilities: &[]Vulnerability{
				{
					ID: "CVE-0000-0000",
					Ratings: &[]VulnerabilityRating{
						{Score: &zero},
					},
				},
			},
		}

		var bomCopy BOM
		require.NoError(t, bom.copy(&bomCopy))

		require.NotNil(t, bomCopy.Vulnerabilities)
		require.Len(t, *bomCopy.Vulnerabilities, 1)
		ratings := (*bomCopy.Vulnerabilities)[0].Ratings
		require.NotNil(t, ratings)
		require.Len(t, *ratings, 1)

		score := (*ratings)[0].Score
		require.NotNil(t, score, "score of 0 must survive the copy, not become nil")
		assert.Equal(t, 0.0, *score)
	})

	t.Run("preserves non-zero values", func(t *testing.T) {
		score := 5.5
		bom := BOM{
			Vulnerabilities: &[]Vulnerability{
				{Ratings: &[]VulnerabilityRating{{Score: &score}}},
			},
		}

		var bomCopy BOM
		require.NoError(t, bom.copy(&bomCopy))

		got := (*(*bomCopy.Vulnerabilities)[0].Ratings)[0].Score
		require.NotNil(t, got)
		assert.Equal(t, 5.5, *got)
		assert.NotSame(t, &score, got, "copy must not alias the source pointer")
	})

	t.Run("keeps nil pointers nil", func(t *testing.T) {
		bom := BOM{
			Vulnerabilities: &[]Vulnerability{
				{Ratings: &[]VulnerabilityRating{{Severity: SeverityHigh}}},
			},
		}

		var bomCopy BOM
		require.NoError(t, bom.copy(&bomCopy))

		rating := (*(*bomCopy.Vulnerabilities)[0].Ratings)[0]
		assert.Nil(t, rating.Score)
		assert.Equal(t, SeverityHigh, rating.Severity)
	})

	t.Run("keeps nil and empty slices distinct", func(t *testing.T) {
		bom := BOM{
			Components:   &[]Component{{Name: "a", Components: &[]Component{}}},
			Dependencies: nil,
		}

		var bomCopy BOM
		require.NoError(t, bom.copy(&bomCopy))

		assert.Nil(t, bomCopy.Dependencies)
		inner := (*bomCopy.Components)[0].Components
		require.NotNil(t, inner)
		assert.NotNil(t, *inner, "empty slice must stay empty, not become nil")
		assert.Empty(t, *inner)
	})

	t.Run("encoding a BOM keeps a score of 0 (issue #304)", func(t *testing.T) {
		zero := 0.0
		bom := NewBOM()
		bom.Vulnerabilities = &[]Vulnerability{
			{ID: "CVE-0000-0000", Ratings: &[]VulnerabilityRating{{Score: &zero}}},
		}

		var buf bytes.Buffer
		err := NewBOMEncoder(&buf, BOMFileFormatJSON).SetPretty(true).EncodeVersion(bom, SpecVersion1_6)
		require.NoError(t, err)
		assert.Contains(t, buf.String(), `"score": 0`)
	})
}
