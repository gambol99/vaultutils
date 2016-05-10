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

// AddGenericSecrets adds a generic secret
func (r vaultctl) AddGenericSecrets(path string, values map[string]string) error {

	return nil
}

// RemoveGenericSecret remove a secret
func (r vaultctl) RemoveGenericSecret(path string) error {

	return nil
}

// ListGenericSecrets lists all the secrets under a path
func (r vaultctl) ListGenericSecrets(string) ([]string, error) {

	return []string{}, nil
}
