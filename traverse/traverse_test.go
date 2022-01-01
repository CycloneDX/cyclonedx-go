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

package traverse

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
)

func TestTraverse(t *testing.T) {
	bom := &cyclonedx.BOM{
		Metadata: &cyclonedx.Metadata{
			Component: &cyclonedx.Component{
				Name: "main",
				Components: &[]cyclonedx.Component{
					{
						Name: "main2",
					},
				},
			},
		},
		Components: &[]cyclonedx.Component{
			{
				Name: "c1",
				Components: &[]cyclonedx.Component{
					{
						Name: "c1.1",
					},
				},
			},
		},
		Dependencies: &[]cyclonedx.Dependency{
			{
				Ref: "d1",
				Dependencies: &[]cyclonedx.Dependency{
					{
						Ref: "d1.1",
					},
				},
			},
		},
	}

	t.Run("Flat", func(t *testing.T) {
		bom, err := bom.Copy()
		require.NoError(t, err)

		err = Traverse(bom, Options{Wants: []Want{WantComponent, WantDependency}}, func(e interface{}) error {
			switch elem := e.(type) {
			case *cyclonedx.Component:
				elem.BOMRef = "x"
			case *cyclonedx.Dependency:
				elem.Ref = "y"
			default:
				require.Fail(t, "traversal over unwanted element of type %T", elem)
			}

			return nil
		})
		require.NoError(t, err)

		require.Equal(t, "x", bom.Metadata.Component.BOMRef)
		require.Equal(t, "", (*bom.Metadata.Component.Components)[0].BOMRef)
		require.Equal(t, "x", (*bom.Components)[0].BOMRef)
		require.Equal(t, "", (*(*bom.Components)[0].Components)[0].BOMRef)

		require.Equal(t, "y", (*bom.Dependencies)[0].Ref)
		require.Equal(t, "d1.1", (*(*bom.Dependencies)[0].Dependencies)[0].Ref)
	})

	t.Run("Recursive", func(t *testing.T) {
		bom, err := bom.Copy()
		require.NoError(t, err)

		err = Traverse(bom, Options{Wants: []Want{WantComponent, WantDependency}, Recursive: true}, func(e interface{}) error {
			switch elem := e.(type) {
			case *cyclonedx.Component:
				elem.BOMRef = "x"
			case *cyclonedx.Dependency:
				elem.Ref = "y"
			default:
				require.Fail(t, "traversal over unwanted element of type %T", elem)
			}

			return nil
		})
		require.NoError(t, err)

		require.Equal(t, "x", bom.Metadata.Component.BOMRef)
		require.Equal(t, "x", (*bom.Metadata.Component.Components)[0].BOMRef)
		require.Equal(t, "x", (*bom.Components)[0].BOMRef)
		require.Equal(t, "x", (*(*bom.Components)[0].Components)[0].BOMRef)

		require.Equal(t, "y", (*bom.Dependencies)[0].Ref)
		require.Equal(t, "y", (*(*bom.Dependencies)[0].Dependencies)[0].Ref)
	})

	t.Run("All", func(t *testing.T) {
		bom, err := bom.Copy()
		require.NoError(t, err)

		err = Traverse(bom, Options{Wants: []Want{WantAll}}, func(e interface{}) error {
			switch e.(type) {
			case *cyclonedx.Metadata:
				break
			case *cyclonedx.Component:
				break
			case *cyclonedx.Dependency:
				break
			default:
				require.Failf(t, "traversal over unwanted element", "element type is %T", e)
			}

			return nil
		})
		require.NoError(t, err)
	})
}
