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
	"net/url"
	"regexp"
	"strconv"

	"github.com/google/uuid"
)

var bomLinkRegex = regexp.MustCompile(`^urn:cdx:(?P<serialNumber>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/(?P<version>[0-9]+)(?:#(?P<bomRef>[0-9a-zA-Z\-._~%!$&'()*+,;=:@\/?]+))?$`)

// IsBOMLink TODO
func IsBOMLink(s string) bool {
	return bomLinkRegex.MatchString(s)
}

// BOMLink TODO
type BOMLink struct {
	SerialNumber uuid.UUID // Serial number of the linked BOM
	Version      int       // Version of the linked BOM
	Reference    string    // Reference of the linked element
}

// NewBOMLink TODO
func NewBOMLink(bom *BOM, elem referrer) (*BOMLink, error) {
	if bom == nil {
		return nil, fmt.Errorf("bom is nil")
	}
	if bom.SerialNumber == "" {
		return nil, fmt.Errorf("missing serial number")
	}
	if bom.Version < 1 {
		return nil, fmt.Errorf("versions below 1 are not allowed")
	}

	serial, err := uuid.Parse(bom.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("invalid serial number: %w", err)
	}

	if elem == nil {
		return &BOMLink{
			SerialNumber: serial,
			Version:      bom.Version,
		}, nil
	}

	return &BOMLink{
		SerialNumber: serial,
		Version:      bom.Version,
		Reference:    elem.bomReference(),
	}, nil
}

// String TODO
func (b BOMLink) String() string {
	if b.Reference == "" {
		return fmt.Sprintf("urn:cdx:%s/%d", b.SerialNumber, b.Version)
	}

	return fmt.Sprintf("urn:cdx:%s/%d#%s", b.SerialNumber, b.Version, url.QueryEscape(b.Reference))
}

// ParseBOMLink TODO
func ParseBOMLink(s string) (*BOMLink, error) {
	matches := bomLinkRegex.FindStringSubmatch(s)
	if len(matches) < 3 || len(matches) > 4 {
		return nil, fmt.Errorf("")
	}

	serial, err := uuid.Parse(matches[1])
	if err != nil {
		return nil, fmt.Errorf("invalid serial number: %w", err)
	}
	version, err := strconv.Atoi(matches[2])
	if err != nil {
		return nil, fmt.Errorf("invalid version: %w", err)
	}

	if len(matches) == 4 {
		bomRef, err := url.QueryUnescape(matches[3])
		if err != nil {
			return nil, fmt.Errorf("invalid reference: %w", err)
		}

		return &BOMLink{
			SerialNumber: serial,
			Version:      version,
			Reference:    bomRef,
		}, nil
	}

	return &BOMLink{
		SerialNumber: serial,
		Version:      version,
	}, nil
}
