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

	"github.com/google/uuid"
	"github.com/mitchellh/copystructure"
)

func MergeFlat(subject *Component, boms ...*BOM) (*BOM, error) {
	if len(boms) < 2 {
		return nil, fmt.Errorf("merging requires at least two boms, but got %d", len(boms))
	}

	if subject != nil && subject.BOMRef == "" {
		bomRef, err := subject.generateBOMReference()
		if err != nil {
			return nil, fmt.Errorf("failed to generate bom ref for subject: %w", err)
		}

		subject.setBOMReference(bomRef)
	}

	serialsSeen := make(map[string]int)
	for i, bom := range boms {
		if bom == nil {
			return nil, fmt.Errorf("bom #%d is nil", i)
		}
		if bom.SerialNumber == "" {
			return nil, fmt.Errorf("bom #%d is missing a serial number", i)
		}
		if _, err := uuid.Parse(bom.SerialNumber); err != nil {
			return nil, fmt.Errorf("bom #%d has an invalid serial number: %w", i, err)
		}
		if seenAt, seen := serialsSeen[bom.SerialNumber]; seen {
			return nil, fmt.Errorf("bom #%d has the same serial number as bom #%d", i, seenAt)
		} else {
			serialsSeen[bom.SerialNumber] = i
		}
	}

	var (
		tools               []Tool
		metadataProperties  []Property
		components          []Component
		services            []Service
		vulnerabilities     []Vulnerability
		dependencies        []Dependency
		compositions        []Composition
		properties          []Property
		subjectDependencies []Dependency
	)

	// During the merging process, BOM refs will be replaced with
	// BOM links. Because BOM refs may be referenced in multiple places
	// throughout the BOM, we need to keep track of the replacements
	// we made.
	replacedRefs := make(map[string]string)

	for i := range boms {
		bom, err := copyBOM(boms[i])
		if err != nil {
			return nil, fmt.Errorf("failed to copy bom #%d", i)
		}

		if bom.Metadata != nil {
			if bom.Metadata.Tools != nil {
				tools = append(tools, *bom.Metadata.Tools...)
			}
			if bom.Metadata.Component != nil {
				err = bomRefsToBomLinks(bom.Metadata.Component, bom, replacedRefs)
				if err != nil {
					return nil, fmt.Errorf("failed to convert refs to links for main component of bom #%d: %w", i, err)
				}

				components = append(components, *bom.Metadata.Component)
				subjectDependencies = append(subjectDependencies, Dependency{Ref: bom.Metadata.Component.BOMRef})
			}
			if bom.Metadata.Properties != nil {
				metadataProperties = append(metadataProperties, *bom.Metadata.Properties...)
			}
		}

		if bom.Components != nil {
			for j := range *bom.Components {
				err = bomRefsToBomLinks(&(*bom.Components)[j], bom, replacedRefs)
				if err != nil {
					return nil, fmt.Errorf("failed to convert refs to links for component #%d of bom #%d: %w", j, i, err)
				}

				components = append(components, (*bom.Components)[j])
			}
		}

		if bom.Services != nil {
			for j := range *bom.Services {
				err = bomRefsToBomLinks(&(*bom.Services)[j], bom, replacedRefs)
				if err != nil {
					return nil, fmt.Errorf("failed to convert refs to links for service #%d of bom #%d: %w", j, i, err)
				}

				services = append(services, (*bom.Services)[j])
			}
		}

		if bom.Vulnerabilities != nil {
			for j, vulnerability := range *bom.Vulnerabilities {
				err = bomRefsToBomLinks(&(*bom.Vulnerabilities)[j], bom, replacedRefs)
				if err != nil {
					return nil, fmt.Errorf("failed to convert refs to links for vulnerability #%d of bom #%d: %w", j, i, err)
				}

				if vulnerability.Affects != nil {
					// Update BOM refs of affected elements
					for k, affects := range *(*bom.Vulnerabilities)[j].Affects {
						if replacement, replaced := replacedRefs[affects.Ref]; replaced {
							(*(*bom.Vulnerabilities)[j].Affects)[k].Ref = replacement
						}
					}
				}

				vulnerabilities = append(vulnerabilities, (*bom.Vulnerabilities)[j])
			}
		}

		if bom.Dependencies != nil {
			updateDependencyRefs(*bom.Dependencies, replacedRefs)
			dependencies = append(dependencies, *bom.Dependencies...)
		}

		if bom.Compositions != nil {
			for j, composition := range *bom.Compositions {
				if composition.Assemblies != nil {
					// Update assembly BOM refs
					for k, ref := range *(*bom.Compositions)[j].Assemblies {
						if replacement, replaced := replacedRefs[string(ref)]; replaced {
							(*(*bom.Compositions)[j].Assemblies)[k] = BOMReference(replacement)
						}
					}
				}
				if composition.Dependencies != nil {
					// Update dependency BOM refs
					for k, ref := range *(*bom.Compositions)[j].Dependencies {
						if replacement, replaced := replacedRefs[string(ref)]; replaced {
							(*(*bom.Compositions)[j].Dependencies)[k] = BOMReference(replacement)
						}
					}
				}

				compositions = append(compositions, (*bom.Compositions)[j])
			}
		}
	}

	if subject != nil {
		// Ensure that dependency relationships of
		// the subject are always on top
		dependencies = append([]Dependency{
			{
				Ref:          subject.BOMRef,
				Dependencies: &subjectDependencies,
			},
		}, dependencies...)
	}

	bom := NewBOM()

	var metadata Metadata
	if len(tools) > 0 {
		metadata.Tools = &tools
	}
	if subject != nil {
		metadata.Component = subject
	}
	if len(metadataProperties) > 0 {
		metadata.Properties = &metadataProperties
	}
	if metadata != (Metadata{}) {
		bom.Metadata = &metadata
	}

	if len(components) > 0 {
		bom.Components = &components
	}
	if len(services) > 0 {
		bom.Services = &services
	}
	if len(vulnerabilities) > 0 {
		bom.Vulnerabilities = &vulnerabilities
	}
	if len(dependencies) > 0 {
		bom.Dependencies = &dependencies
	}
	if len(compositions) > 0 {
		bom.Compositions = &compositions
	}
	if len(properties) > 0 {
		bom.Properties = &properties
	}

	return bom, nil
}

func MergeLink(subject *Component, boms ...*BOM) (*BOM, error) {
	if len(boms) < 2 {
		return nil, fmt.Errorf("merging requires at least two boms, but got %d", len(boms))
	}

	if subject != nil && subject.BOMRef == "" {
		bomRef, err := subject.generateBOMReference()
		if err != nil {
			return nil, fmt.Errorf("failed to generate bom ref for subject: %w", err)
		}

		subject.setBOMReference(bomRef)
	}

	var (
		components          []Component
		dependencies        []Dependency
		subjectDependencies []Dependency
	)

	serialsSeen := make(map[string]int)
	for i, bom := range boms {
		if bom == nil {
			return nil, fmt.Errorf("bom #%d is nil", i)
		}
		if bom.SerialNumber == "" {
			return nil, fmt.Errorf("bom #%d is missing a serial number", i)
		}
		if _, err := uuid.Parse(bom.SerialNumber); err != nil {
			return nil, fmt.Errorf("bom #%d has an invalid serial number: %w", i, err)
		}
		if seenAt, seen := serialsSeen[bom.SerialNumber]; seen {
			return nil, fmt.Errorf("bom #%d has the same serial number as bom #%d", i, seenAt)
		} else {
			serialsSeen[bom.SerialNumber] = i
		}
		if bom.Metadata == nil || bom.Metadata.Component == nil {
			return nil, fmt.Errorf("bom #%s is missing a main component", bom.SerialNumber)
		}

		bomLink, err := NewBOMLink(bom, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to link bom #%d: %w", i, err)
		}

		component := Component{
			BOMRef:  bom.Metadata.Component.BOMRef,
			Type:    bom.Metadata.Component.Type,
			Group:   bom.Metadata.Component.Group,
			Name:    bom.Metadata.Component.Name,
			Version: bom.Metadata.Component.Version,
			ExternalReferences: &[]ExternalReference{
				{
					Type: ERTypeBOM,
					URL:  bomLink.String(),
				},
			},
		}

		if component.BOMRef == "" {
			component.BOMRef, err = component.generateBOMReference()
			if err != nil {
				return nil, fmt.Errorf("failed to generate bom ref for main component of bom #%d: %w", i, err)
			}
		}

		err = bomRefsToBomLinks(&component, bom, make(map[string]string))
		if err != nil {
			return nil, fmt.Errorf("failed to convert refs to links for main component of bom #%d: %w", i, err)
		}

		components = append(components, component)

		if subject != nil {
			subjectDependencies = append(subjectDependencies, Dependency{
				Ref: component.BOMRef,
			})
		}
	}

	if subject != nil {
		// Ensure that dependency relationships of
		// the subject are always on top
		dependencies = append([]Dependency{
			{
				Ref:          subject.BOMRef,
				Dependencies: &subjectDependencies,
			},
		}, subjectDependencies...)
	}

	bom := NewBOM()
	if subject != nil {
		bom.Metadata = &Metadata{
			Component: subject,
		}
	}
	if len(components) > 0 {
		bom.Components = &components
	}
	if len(dependencies) > 0 {
		bom.Dependencies = &dependencies
	}

	return bom, nil
}

func copyBOM(bom *BOM) (*BOM, error) {
	bomCopy, err := copystructure.Copy(bom)
	if err != nil {
		return nil, err
	}

	return bomCopy.(*BOM), nil
}

func bomRefsToBomLinks(ref referrer, bom *BOM, replacedRefs map[string]string) error {
	if ref == nil {
		return nil
	}

	if ref.bomReference() == "" {
		bomRef, err := ref.generateBOMReference()
		if err != nil {
			return fmt.Errorf("failed to generate bom reference: %w", err)
		}

		ref.setBOMReference(bomRef)
	}

	if !IsBOMLink(ref.bomReference()) {
		link, err := NewBOMLink(bom, ref)
		if err != nil {
			return fmt.Errorf("failed to create bom link: %w", err)
		}

		replacedRefs[ref.bomReference()] = link.String()
		ref.setBOMReference(link.String())
	}

	switch elemType := ref.(type) {
	case *Component:
		if elemType.Components != nil {
			for i := range *elemType.Components {
				err := bomRefsToBomLinks(&(*elemType.Components)[i], bom, replacedRefs)
				if err != nil {
					return err
				}
			}
		}
	case *Service:
		if elemType.Services != nil {
			for i := range *elemType.Services {
				err := bomRefsToBomLinks(&(*elemType.Services)[i], bom, replacedRefs)
				if err != nil {
					return err
				}
			}
		}
	case *Vulnerability:
		break // There are not sub-vulnerabilities
	default:
		return fmt.Errorf("can't handle element of type %T", elemType)
	}

	return nil
}

func updateDependencyRefs(dependencies []Dependency, replacedRefs map[string]string) {
	for i, dependency := range dependencies {
		if replacement, replaced := replacedRefs[dependency.Ref]; replaced {
			dependencies[i].Ref = replacement
		}

		if dependency.Dependencies != nil {
			updateDependencyRefs(*dependencies[i].Dependencies, replacedRefs)
		}
	}
}
