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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBOMJSONInlineSignatureRoundTrip(t *testing.T) {
	input := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"signature":{"algorithm":"RS512","value":"signature"}}`)

	var bom BOM
	require.NoError(t, NewBOMDecoder(bytes.NewReader(input), BOMFileFormatJSON).Decode(&bom))
	require.NotNil(t, bom.Signature)
	require.Equal(t, "RS512", bom.Signature.Algorithm)

	var encoded bytes.Buffer
	require.NoError(t, NewBOMEncoder(&encoded, BOMFileFormatJSON).Encode(&bom))

	var roundTripped BOM
	require.NoError(t, NewBOMDecoder(&encoded, BOMFileFormatJSON).Decode(&roundTripped))
	require.NotNil(t, roundTripped.Signature)
	require.Equal(t, "RS512", roundTripped.Signature.Algorithm)
	require.Equal(t, "signature", roundTripped.Signature.Value)
}

func TestJSFSignatureJSONInlineRoundTrip(t *testing.T) {
	input := []byte(`{"algorithm":"RS512","keyId":"key-1","publicKey":{"kty":"RSA","n":"modulus","e":"AQAB"},"certificatePath":["certificate"],"excludes":["signature"],"value":"signature"}`)

	var signature JSFSignature
	require.NoError(t, json.Unmarshal(input, &signature))
	require.NotNil(t, signature.JSFSigner)
	require.Equal(t, "RS512", signature.Algorithm)
	require.Equal(t, "key-1", signature.KeyID)
	require.Equal(t, "RSA", signature.PublicKey.KTY)
	require.Equal(t, []string{"certificate"}, *signature.CertificatePath)
	require.Equal(t, []string{"signature"}, *signature.Excludes)
	require.Equal(t, "signature", signature.Value)

	encoded, err := json.Marshal(signature)
	require.NoError(t, err)
	require.JSONEq(t, string(input), string(encoded))
}

func TestJSFSignerJSONIncludesRequiredEmptyValues(t *testing.T) {
	encoded, err := json.Marshal(JSFSigner{})
	require.NoError(t, err)
	require.JSONEq(t, `{"algorithm":"","value":""}`, string(encoded))

	encoded, err = json.Marshal(JSFSignature{JSFSigner: &JSFSigner{}})
	require.NoError(t, err)
	require.JSONEq(t, `{"algorithm":"","value":""}`, string(encoded))
}

func TestJSFSignatureJSONMultipleSigners(t *testing.T) {
	input := []byte(`{"signers":[{"algorithm":"ES256","value":"first"},{"algorithm":"RS512","value":"second"}]}`)

	var signature JSFSignature
	require.NoError(t, json.Unmarshal(input, &signature))
	require.NotNil(t, signature.JSFSigner)
	require.Empty(t, signature.Algorithm)
	require.Len(t, *signature.Signers, 2)
	require.Equal(t, "ES256", (*signature.Signers)[0].Algorithm)

	encoded, err := json.Marshal(signature)
	require.NoError(t, err)
	require.JSONEq(t, string(input), string(encoded))
}

func TestJSFSignatureJSONCertificateChain(t *testing.T) {
	input := []byte(`{"chain":[{"algorithm":"ES512","value":"leaf"},{"algorithm":"ES512","value":"issuer"}]}`)

	var signature JSFSignature
	require.NoError(t, json.Unmarshal(input, &signature))
	require.NotNil(t, signature.JSFSigner)
	require.Empty(t, signature.Algorithm)
	require.Len(t, *signature.Chain, 2)
	require.Equal(t, "ES512", (*signature.Chain)[0].Algorithm)

	encoded, err := json.Marshal(signature)
	require.NoError(t, err)
	require.JSONEq(t, string(input), string(encoded))
}
