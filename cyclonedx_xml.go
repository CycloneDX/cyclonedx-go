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
	"encoding/xml"
	"errors"
	"fmt"
	"io"
)

// bomReferenceXML is temporarily used for marshalling and unmarshalling
// BOMReference instances to and from XML.
type bomReferenceXML struct {
	Ref string `json:"-" xml:"ref,attr"`
}

func (b BOMReference) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement(bomReferenceXML{Ref: string(b)}, start)
}

func (b *BOMReference) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	bXML := bomReferenceXML{}
	if err := d.DecodeElement(&bXML, &start); err != nil {
		return err
	}
	*b = BOMReference(bXML.Ref)
	return nil
}

func (c Copyright) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement(c.Text, start)
}

func (c *Copyright) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var text string
	if err := d.DecodeElement(&text, &start); err != nil {
		return err
	}
	c.Text = text
	return nil
}

// dependencyXML is temporarily used for marshalling and unmarshalling
// Dependency instances to and from XML.
type dependencyXML struct {
	Ref          string           `xml:"ref,attr"`
	Dependencies *[]dependencyXML `xml:"dependency,omitempty"`
}

func (d Dependency) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	xmlDep := dependencyXML{Ref: d.Ref}

	if d.Dependencies != nil && len(*d.Dependencies) > 0 {
		xmlDeps := make([]dependencyXML, len(*d.Dependencies))
		for i := range *d.Dependencies {
			xmlDeps[i] = dependencyXML{Ref: (*d.Dependencies)[i]}
		}
		xmlDep.Dependencies = &xmlDeps
	}

	return e.EncodeElement(xmlDep, start)
}

func (d *Dependency) UnmarshalXML(dec *xml.Decoder, start xml.StartElement) error {
	xmlDep := dependencyXML{}
	err := dec.DecodeElement(&xmlDep, &start)
	if err != nil {
		return err
	}

	dep := Dependency{Ref: xmlDep.Ref}
	if xmlDep.Dependencies != nil && len(*xmlDep.Dependencies) > 0 {
		deps := make([]string, len(*xmlDep.Dependencies))
		for i := range *xmlDep.Dependencies {
			deps[i] = (*xmlDep.Dependencies)[i].Ref
		}
		dep.Dependencies = &deps
	}

	*d = dep
	return nil
}

func (ev EnvironmentVariables) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if len(ev) == 0 {
		return nil
	}

	err := e.EncodeToken(start)
	if err != nil {
		return err
	}

	for _, choice := range ev {
		if choice.Property != nil && choice.Value != "" {
			return fmt.Errorf("either property or value must be set, but not both")
		}

		if choice.Property != nil {
			err = e.EncodeElement(choice.Property, xml.StartElement{Name: xml.Name{Local: "environmentVar"}})
			if err != nil {
				return err
			}
		} else if choice.Value != "" {
			err = e.EncodeElement(choice.Value, xml.StartElement{Name: xml.Name{Local: "value"}})
			if err != nil {
				return err
			}
		}
	}

	return e.EncodeToken(start.End())
}

func (ev *EnvironmentVariables) UnmarshalXML(d *xml.Decoder, _ xml.StartElement) error {
	envVars := make([]EnvironmentVariableChoice, 0)

	for {
		token, err := d.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}

		switch tokenType := token.(type) {
		case xml.StartElement:
			if tokenType.Name.Local == "value" {
				var value string
				err = d.DecodeElement(&value, &tokenType)
				if err != nil {
					return err
				}
				envVars = append(envVars, EnvironmentVariableChoice{Value: value})
			} else if tokenType.Name.Local == "environmentVar" {
				var property Property
				err = d.DecodeElement(&property, &tokenType)
				if err != nil {
					return err
				}
				envVars = append(envVars, EnvironmentVariableChoice{Property: &property})
			} else {
				return fmt.Errorf("unknown element: %s", tokenType.Name.Local)
			}
		}
	}

	*ev = envVars
	return nil
}

func (l Licenses) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if len(l) == 0 {
		return nil
	}

	if err := e.EncodeToken(start); err != nil {
		return err
	}

	for _, choice := range l {
		if choice.License != nil && choice.Expression != "" {
			return fmt.Errorf("either license or expression must be set, but not both")
		}

		if choice.License != nil {
			if err := e.EncodeElement(choice.License, xml.StartElement{Name: xml.Name{Local: "license"}}); err != nil {
				return err
			}
		} else if choice.Expression != "" {
			if err := e.EncodeElement(choice.Expression, xml.StartElement{Name: xml.Name{Local: "expression"}}); err != nil {
				return err
			}
		}
	}

	return e.EncodeToken(start.End())
}

func (l *Licenses) UnmarshalXML(d *xml.Decoder, _ xml.StartElement) error {
	licenses := make([]LicenseChoice, 0)

	for {
		token, err := d.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}

		switch tokenType := token.(type) {
		case xml.StartElement:
			if tokenType.Name.Local == "expression" {
				var expression string
				if err = d.DecodeElement(&expression, &tokenType); err != nil {
					return err
				}
				licenses = append(licenses, LicenseChoice{Expression: expression})
			} else if tokenType.Name.Local == "license" {
				var license License
				if err = d.DecodeElement(&license, &tokenType); err != nil {
					return err
				}
				licenses = append(licenses, LicenseChoice{License: &license})
			} else {
				return fmt.Errorf("unknown element: %s", tokenType.Name.Local)
			}
		}
	}

	*l = licenses
	return nil
}

type mlDatasetChoiceRefXML struct {
	Ref string `json:"-" xml:"ref"`
}

type mlDatasetChoiceXML struct {
	Ref string `json:"-" xml:"ref"`
	ComponentData
}

func (dc MLDatasetChoice) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if dc.Ref != "" {
		return e.EncodeElement(mlDatasetChoiceRefXML{Ref: dc.Ref}, start)
	} else if dc.ComponentData != nil {
		return e.EncodeElement(dc.ComponentData, start)
	}

	return nil
}

func (dc *MLDatasetChoice) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var choice mlDatasetChoiceXML
	err := d.DecodeElement(&choice, &start)
	if err != nil {
		return err
	}

	if choice.Ref != "" {
		dc.Ref = choice.Ref
		return nil
	}

	if choice.ComponentData != (ComponentData{}) {
		dc.ComponentData = &choice.ComponentData
	}

	return nil
}

func (sv SpecVersion) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement(sv.String(), start)
}

func (sv *SpecVersion) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var v string
	err := d.DecodeElement(&v, &start)
	if err != nil {
		return err
	}

	switch v {
	case SpecVersion1_0.String():
		*sv = SpecVersion1_0
	case SpecVersion1_1.String():
		*sv = SpecVersion1_1
	case SpecVersion1_2.String():
		*sv = SpecVersion1_2
	case SpecVersion1_3.String():
		*sv = SpecVersion1_3
	case SpecVersion1_4.String():
		*sv = SpecVersion1_4
	case SpecVersion1_5.String():
		*sv = SpecVersion1_5
	default:
		return ErrInvalidSpecVersion
	}

	return nil
}

// toolsChoiceMarshalXML is a helper struct for marshalling ToolsChoice.
type toolsChoiceMarshalXML struct {
	LegacyTools *[]Tool      `json:"-" xml:"tool,omitempty"`
	Components  *[]Component `json:"-" xml:"components>component,omitempty"`
	Services    *[]Service   `json:"-" xml:"services>service,omitempty"`
}

// toolsChoiceUnmarshalXML is a helper struct for unmarshalling tools represented
// as components and / or services. It is intended to be used with the streaming XML API.
//
//	<components>   <-- cursor should be here when unmarshalling this!
//	  <component>
//	    <name>foo</name>
//	  </component>
//	</components>
type toolsChoiceUnmarshalXML struct {
	Components *[]Component `json:"-" xml:"component,omitempty"`
	Services   *[]Service   `json:"-" xml:"service,omitempty"`
}

func (tc ToolsChoice) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if tc.Tools != nil && (tc.Components != nil || tc.Services != nil) {
		return fmt.Errorf("either a list of tools, or an object holding components and services can be used, but not both")
	}

	if tc.Tools != nil {
		return e.EncodeElement(toolsChoiceMarshalXML{LegacyTools: tc.Tools}, start)
	}

	tools := toolsChoiceMarshalXML{
		Components: tc.Components,
		Services:   tc.Services,
	}
	if tools.Components != nil || tools.Services != nil {
		return e.EncodeElement(tools, start)
	}

	return nil
}

func (tc *ToolsChoice) UnmarshalXML(d *xml.Decoder, _ xml.StartElement) error {
	var components []Component
	var services []Service
	legacyTools := make([]Tool, 0)

	for {
		token, err := d.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}

		switch tokenType := token.(type) {
		case xml.StartElement:
			if tokenType.Name.Local == "tool" {
				var tool Tool
				if err = d.DecodeElement(&tool, &tokenType); err != nil {
					return err
				}
				legacyTools = append(legacyTools, tool)
			} else if tokenType.Name.Local == "components" {
				var foo toolsChoiceUnmarshalXML
				if err = d.DecodeElement(&foo, &tokenType); err != nil {
					return err
				}
				if foo.Components != nil {
					components = *foo.Components
				}
			} else if tokenType.Name.Local == "services" {
				var foo toolsChoiceUnmarshalXML
				if err = d.DecodeElement(&foo, &tokenType); err != nil {
					return err
				}
				if foo.Services != nil {
					services = *foo.Services
				}
			} else {
				return fmt.Errorf("unknown element: %s", tokenType.Name.Local)
			}
		}
	}

	choice := ToolsChoice{}
	if len(legacyTools) > 0 && (len(components) > 0 || len(services) > 0) {
		return fmt.Errorf("either a list of tools, or an object holding components and services can be used, but not both")
	}
	if len(components) > 0 {
		choice.Components = &components
	}
	if len(services) > 0 {
		choice.Services = &services
	}
	if len(legacyTools) > 0 {
		choice.Tools = &legacyTools
	}

	if choice.Tools != nil || choice.Components != nil || choice.Services != nil {
		*tc = choice
	}

	return nil
}

var xmlNamespaces = map[SpecVersion]string{
	SpecVersion1_0: "http://cyclonedx.org/schema/bom/1.0",
	SpecVersion1_1: "http://cyclonedx.org/schema/bom/1.1",
	SpecVersion1_2: "http://cyclonedx.org/schema/bom/1.2",
	SpecVersion1_3: "http://cyclonedx.org/schema/bom/1.3",
	SpecVersion1_4: "http://cyclonedx.org/schema/bom/1.4",
	SpecVersion1_5: "http://cyclonedx.org/schema/bom/1.5",
}
