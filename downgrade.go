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

import "fmt"

// downgrade "downgrades" the BOM to a given version of the specification.
// Downgrading works by successively removing (or changing) fields introduced in later specification versions.
// This procedure has been adapted from the .NET implementation:
// https://github.com/CycloneDX/cyclonedx-dotnet-library/blob/v5.2.2/src/CycloneDX.Core/BomUtils.cs#L60
func (b *BOM) downgrade(version SpecVersion) error {
	if version < SpecVersion1_1 {
		b.SerialNumber = ""
		b.ExternalReferences = nil
		forEachComponent(b.Components, func(c *Component) {
			c.BOMRef = ""
			c.ExternalReferences = nil
			if c.Licenses != nil {
				// Keep track of licenses that are still valid
				// after removal of unsupported fields.
				validLicenses := make(Licenses, 0)

				for i := range *c.Licenses {
					license := &(*c.Licenses)[i]
					if license.License != nil {
						license.License.Text = nil
						license.License.URL = ""
					}
					license.Expression = ""
					if license.License != nil {
						validLicenses = append(validLicenses, *license)
					}
				}

				// Remove the licenses node entirely if no valid licenses
				// are left. This avoids empty (thus invalid) <licenses> tags in XML.
				if len(validLicenses) == 0 {
					c.Licenses = nil
				} else {
					c.Licenses = &validLicenses
				}
			}
			if c.Modified == nil {
				c.Modified = Bool(false)
			}
			c.Pedigree = nil
		})
	}

	if version < SpecVersion1_2 {
		b.Metadata = nil
		b.Dependencies = nil
		b.Services = nil
		forEachComponent(b.Components, func(c *Component) {
			c.Author = ""
			c.MIMEType = ""
			c.Supplier = nil
			c.SWID = nil
			if c.Pedigree != nil {
				c.Pedigree.Patches = nil
			}
		})
	}

	if version < SpecVersion1_3 {
		b.Compositions = nil
		if b.Metadata != nil {
			b.Metadata.Licenses = nil
			b.Metadata.Properties = nil
		}
		forEachComponent(b.Components, func(c *Component) {
			c.Evidence = nil
			c.Properties = nil
			if c.ExternalReferences != nil {
				for i := range *c.ExternalReferences {
					(*c.ExternalReferences)[i].Hashes = nil
				}
			}
		})
		forEachService(b.Services, func(s *Service) {
			s.Properties = nil
			if s.ExternalReferences != nil {
				for i := range *s.ExternalReferences {
					(*s.ExternalReferences)[i].Hashes = nil
				}
			}
		})
	}

	if version < SpecVersion1_4 {
		if b.Metadata != nil && b.Metadata.Tools != nil {
			for i := range *b.Metadata.Tools {
				(*b.Metadata.Tools)[i].ExternalReferences = nil
			}
		}
		forEachComponent(b.Components, func(c *Component) {
			c.ReleaseNotes = nil
			if c.Version == "" {
				c.Version = "0.0.0"
			}
		})
		forEachService(b.Services, func(s *Service) {
			s.ReleaseNotes = nil
		})
		b.Vulnerabilities = nil
	}

	b.SpecVersion = version
	b.XMLNS = xmlNamespaces[version]

	return nil
}

func (b *BOM) copyAndDowngrade(version SpecVersion) (*BOM, error) {
	var bomCopy BOM
	err := b.copy(&bomCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to copy bom: %w", err)
	}

	err = bomCopy.downgrade(version)
	return &bomCopy, err
}

func forEachComponent(components *[]Component, f func(c *Component)) {
	if components == nil || len(*components) == 0 {
		return
	}

	for i := range *components {
		component := &(*components)[i]
		f(component)
		forEachComponent(component.Components, f)
		if component.Pedigree != nil {
			forEachComponent(component.Pedigree.Ancestors, f)
			forEachComponent(component.Pedigree.Descendants, f)
			forEachComponent(component.Pedigree.Variants, f)
		}
	}
}

func forEachService(services *[]Service, f func(s *Service)) {
	if services == nil || len(*services) == 0 {
		return
	}

	for i := range *services {
		f(&(*services)[i])
		forEachService((*services)[i].Services, f)
	}
}
