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

// Package traverse TODO
package traverse

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Want TODO
type Want int

const (
	WantAll         Want = iota // Will yield elements of all types
	WantMetadata                // Will yield elements of type *Metadata
	WantTool                    // Will yield elements of type *Tool
	WantComponent               // Will yield elements of type *Component
	WantService                 // Will yield elements of type *Service
	WantDependency              // Will yield elements of type *Dependency
	WantComposition             // Will yield elements of type *Composition
)

// Options TODO
type Options struct {
	Wants     []Want // Types of elements to visit
	Recursive bool   // Traverse recursively?
}

func (o Options) isWanted(w Want) bool {
	for i := range o.Wants {
		if o.Wants[i] == w || o.Wants[i] == WantAll {
			return true
		}
	}

	return false
}

// Handler TODO
type Handler func(e interface{}) error

// Traverse TODO
func Traverse(bom *cdx.BOM, opts Options, h Handler) error {
	var err error

	if bom.Metadata != nil {
		if opts.isWanted(WantMetadata) {
			err = h(bom.Metadata)
			if err != nil {
				return err
			}
		}

		if bom.Metadata.Tools != nil && opts.isWanted(WantTool) {
			for i := range *bom.Metadata.Tools {
				err = h(&(*bom.Metadata.Tools)[i])
				if err != nil {
					return err
				}
			}
		}

		if bom.Metadata.Component != nil && opts.isWanted(WantComponent) {
			err = traverseComponent(bom.Metadata.Component, opts.Recursive, h)
			if err != nil {
				return err
			}
		}
	}

	if bom.Components != nil && opts.isWanted(WantComponent) {
		for i := range *bom.Components {
			err = traverseComponent(&(*bom.Components)[i], opts.Recursive, h)
			if err != nil {
				return err
			}
		}
	}

	if bom.Dependencies != nil && opts.isWanted(WantDependency) {
		for i := range *bom.Dependencies {
			err = traverseDependency(&(*bom.Dependencies)[i], opts.Recursive, h)
			if err != nil {
				return err
			}
		}
	}

	if bom.Compositions != nil && opts.isWanted(WantComposition) {
		for i := range *bom.Compositions {
			err = h(&(*bom.Compositions)[i])
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func traverseComponent(c *cdx.Component, recursive bool, h Handler) error {
	if c == nil {
		return nil
	}

	err := h(c)
	if err != nil {
		return err
	}

	if c.Components != nil && recursive {
		for i := range *c.Components {
			err = traverseComponent(&(*c.Components)[i], recursive, h)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func traverseDependency(d *cdx.Dependency, recursive bool, h Handler) error {
	if d == nil {
		return nil
	}

	err := h(d)
	if err != nil {
		return err
	}

	if d.Dependencies != nil && recursive {
		for i := range *d.Dependencies {
			err = traverseDependency(&(*d.Dependencies)[i], recursive, h)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
