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
	"encoding/json"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestMLDatasetChoice_MarshalJSON(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		choice := MLDatasetChoice{}
		jsonBytes, err := json.Marshal(choice)
		require.NoError(t, err)
		require.Equal(t, "{}", string(jsonBytes))
	})

	t.Run("WithRef", func(t *testing.T) {
		choice := MLDatasetChoice{Ref: "foo"}
		jsonBytes, err := json.Marshal(choice)
		require.NoError(t, err)
		require.Equal(t, `{"ref":"foo"}`, string(jsonBytes))
	})

	t.Run("WithComponentData", func(t *testing.T) {
		choice := MLDatasetChoice{
			ComponentData: &ComponentData{
				BOMRef: "foo",
				Name:   "bar",
			},
		}
		jsonBytes, err := json.Marshal(choice)
		require.NoError(t, err)
		require.Equal(t, `{"bom-ref":"foo","name":"bar"}`, string(jsonBytes))
	})

	t.Run("WithRefAndComponentData", func(t *testing.T) {
		choice := MLDatasetChoice{
			Ref: "foo",
			ComponentData: &ComponentData{
				BOMRef: "bar",
				Name:   "baz",
			},
		}
		jsonBytes, err := json.Marshal(choice)
		require.NoError(t, err)
		require.Equal(t, `{"ref":"foo"}`, string(jsonBytes))
	})
}

func TestMLDatasetChoice_UnmarshalJSON(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		var choice MLDatasetChoice
		err := json.Unmarshal([]byte(`{}`), &choice)
		require.NoError(t, err)
		require.Equal(t, MLDatasetChoice{}, choice)
	})

	t.Run("WithRef", func(t *testing.T) {
		var choice MLDatasetChoice
		err := json.Unmarshal([]byte(`{"ref":"foo"}`), &choice)
		require.NoError(t, err)
		require.Equal(t, "foo", choice.Ref)
		require.Nil(t, choice.ComponentData)
	})

	t.Run("WithComponentData", func(t *testing.T) {
		var choice MLDatasetChoice
		err := json.Unmarshal([]byte(`{"bom-ref":"foo","name":"bar"}`), &choice)
		require.NoError(t, err)
		require.Empty(t, choice.Ref)
		require.NotNil(t, choice.ComponentData)
		require.Equal(t, "foo", choice.ComponentData.BOMRef)
		require.Equal(t, "bar", choice.ComponentData.Name)
	})

	t.Run("WithRefAndComponentData", func(t *testing.T) {
		var choice MLDatasetChoice
		err := json.Unmarshal([]byte(`{"ref":"foo","bom-ref":"bar","name":"baz"}`), &choice)
		require.NoError(t, err)
		require.Equal(t, "foo", choice.Ref)
		require.Nil(t, choice.ComponentData)
	})
}
