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
	"strings"
)

// URI returns the uri for the config item
func (r *Attributes) URI() string {
	if x, found := (*r)["uri"]; found {
		return x.(string)
	}

	return ""
}

// IsOneshot checks if the attribute is a oneshot attribute
func (r *Attributes) IsOneshot() bool {
	_, found := (*r)["oneshot"]
	return found
}

// Values retrieves the values from the attributes
func (r *Attributes) Values() map[string]interface{} {
	return (*r)
}

// GetPath returns the uri of the config
func (r *Attributes) GetPath(ns string) string {
	return fmt.Sprintf("%s/%s", ns, r.URI())
}

func (r *Attributes) String() string {
	var items []string
	for k, v := range *r {
		items = append(items, fmt.Sprintf("[%s|%s]", k, v))
	}

	return strings.Join(items, ",")
}

// IsValid validates the attributes
func (r Attributes) IsValid() error {
	if r.URI() == "" {
		return fmt.Errorf("attributes must have a uri specified")
	}

	return nil
}
