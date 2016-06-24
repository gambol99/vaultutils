/*
Copyright 2016 All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package vaultutils

import (
	"bytes"
	"encoding/json"
)

type cfSSLSigningRequest struct {
	Hosts       []string `json:"hosts"`
	Request     string   `json:"certificate_request"`
	Profile     string   `json:"profile"`
	CRLOverride string   `json:"crl_override"`
	Label       string   `json:"label"`
}

//
// SignWithCertificateAuthority request the CSR be signed by CFSSL
//
func (r *vaultctl) SignWithCertificateAuthority(csr, profile string) (string, error) {
	// step: encode the request into json
	request := new(bytes.Buffer)

	// step: json encode the request
	if err := json.NewEncoder(request).Encode(cfSSLSigningRequest{
		Request: csr,
		Profile: profile,
	}); err != nil {
		return "", err
	}

	// step: sign the request
	certificate, err := r.signer.Sign(request.Bytes())
	if err != nil {
		return "", err
	}

	return string(certificate), nil
}
