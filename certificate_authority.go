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
	"fmt"
	"net/url"
)

//
// IsValid checks the authority is valid
//
func (r CertificateAuthority) IsValid() error {
	if r.Token == "" {
		return fmt.Errorf("no token")
	}
	if r.URL == "" {
		return fmt.Errorf("no url")
	}
	if _, err := url.Parse(r.URL); err != nil {
		return fmt.Errorf("invalid url")
	}

	return nil
}
