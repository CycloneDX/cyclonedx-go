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

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

func TestMergeFlat(t *testing.T) {
	t.Run("Components", func(t *testing.T) {
		t.Run("WithoutSubject", func(t *testing.T) {
			var (
				bomA           = readTestBOM(t, "./testdata/merge/components-bom-a.json")
				bomB           = readTestBOM(t, "./testdata/merge/components-bom-b.json")
				resultExpected = readTestBOM(t, "./testdata/merge/components-result-flat.json")
			)

			result, err := MergeFlat(nil, bomA, bomB)
			require.NoError(t, err)

			if !cmp.Equal(result, resultExpected, filterXMLNS) {
				require.FailNow(t, "unexpected merge result", cmp.Diff(result, resultExpected, filterXMLNS))
			}
		})

		t.Run("WithSubject", func(t *testing.T) {
			var (
				bomA           = readTestBOM(t, "./testdata/merge/components-bom-a.json")
				bomB           = readTestBOM(t, "./testdata/merge/components-bom-b.json")
				subject        = readTestBOM(t, "./testdata/merge/components-subject.json").Metadata.Component
				resultExpected = readTestBOM(t, "./testdata/merge/components-result-flat-subject.json")
			)

			result, err := MergeFlat(subject, bomA, bomB)
			require.NoError(t, err)

			if !cmp.Equal(result, resultExpected, filterXMLNS) {
				require.FailNow(t, "unexpected merge result", cmp.Diff(result, resultExpected, filterXMLNS))
			}
		})
	})
}

func TestMergeLink(t *testing.T) {
	t.Run("Components", func(t *testing.T) {
		t.Run("WithoutSubject", func(t *testing.T) {
			var (
				bomA           = readTestBOM(t, "./testdata/merge/components-bom-a.json")
				bomB           = readTestBOM(t, "./testdata/merge/components-bom-b.json")
				resultExpected = readTestBOM(t, "./testdata/merge/components-result-link.json")
			)

			result, err := MergeLink(nil, bomA, bomB)
			require.NoError(t, err)

			if !cmp.Equal(result, resultExpected, filterXMLNS) {
				require.FailNow(t, "unexpected merge result", cmp.Diff(result, resultExpected, filterXMLNS))
			}
		})

		t.Run("WithSubject", func(t *testing.T) {
			var (
				bomA           = readTestBOM(t, "./testdata/merge/components-bom-a.json")
				bomB           = readTestBOM(t, "./testdata/merge/components-bom-b.json")
				subject        = readTestBOM(t, "./testdata/merge/components-subject.json").Metadata.Component
				resultExpected = readTestBOM(t, "./testdata/merge/components-result-link-subject.json")
			)

			result, err := MergeLink(subject, bomA, bomB)
			require.NoError(t, err)

			if !cmp.Equal(result, resultExpected, filterXMLNS) {
				require.FailNow(t, "unexpected merge result", cmp.Diff(result, resultExpected, filterXMLNS))
			}
		})
	})
}

var filterXMLNS = cmp.FilterPath(func(path cmp.Path) bool {
	return path.String() == "XMLNS"
}, cmp.Ignore())
