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
	"reflect"
)

// copy creates a deep copy of the BOM in a given destination.
//
// The copy is done via reflection rather than an encode/decode round trip,
// because gob omits zero values: a pointer to 0 or false would come back nil.
// Nil pointers and nil slices stay nil, and empty slices stay empty, so the
// copy serializes identically to the original.
func (b BOM) copy(dst *BOM) error {
	return deepCopy(reflect.ValueOf(dst).Elem(), reflect.ValueOf(b))
}

// deepCopy recursively copies src into dst, which must be settable and of
// the same type. It returns an error for kinds the BOM does not use today
// (maps, interfaces, channels, ...) so that adding such a field later fails
// loudly instead of producing a silently shallow copy.
func deepCopy(dst, src reflect.Value) error {
	switch src.Kind() {
	case reflect.Pointer:
		if src.IsNil() {
			return nil
		}
		p := reflect.New(src.Elem().Type())
		if err := deepCopy(p.Elem(), src.Elem()); err != nil {
			return err
		}
		dst.Set(p)

	case reflect.Struct:
		for i := 0; i < src.NumField(); i++ {
			if !dst.Field(i).CanSet() {
				return fmt.Errorf("%s.%s: cannot set unexported field", src.Type().Name(), src.Type().Field(i).Name)
			}
			if err := deepCopy(dst.Field(i), src.Field(i)); err != nil {
				return fmt.Errorf("%s.%s: %w", src.Type().Name(), src.Type().Field(i).Name, err)
			}
		}

	case reflect.Slice:
		if src.IsNil() {
			return nil
		}
		s := reflect.MakeSlice(src.Type(), src.Len(), src.Len())
		for i := 0; i < src.Len(); i++ {
			if err := deepCopy(s.Index(i), src.Index(i)); err != nil {
				return err
			}
		}
		dst.Set(s)

	case reflect.Bool, reflect.String,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		dst.Set(src)

	default:
		return fmt.Errorf("deepCopy: unsupported kind %s", src.Kind())
	}

	return nil
}
