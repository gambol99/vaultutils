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
	"net/http"
	"strings"
)

//
// MountAuth creates or updates a auth backend
//
func (r vaultctl) MountAuth(a Auth) error {
	if err := a.IsValid(); err != nil {
		return err
	}
	// step: check if the auth backend is already mounted
	if found, err := r.HasAuth(a.Path); err != nil {
		return err
	} else if !found {
		if err := r.client.Sys().EnableAuth(a.Path, a.Type, a.Description); err != nil {
			return err
		}
	}

	// step: config the backend
	for _, c := range a.Attrs {
		resp, err := r.request("POST", c.GetPath(a.Path), &c)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusNoContent {
			return err
		}
	}

	return nil
}

//
// HasAuth checks if the authentication backend exists
//
func (r vaultctl) HasAuth(path string) (bool, error) {
	list, err := r.ListAuths()
	if err != nil {
		return false, err
	}

	return containedIn(path, list), nil
}

//
// DeleteAuth removes the auth backend
//
func (r vaultctl) DeleteAuth(path string) error {
	if found, err := r.HasAuth(path); err != nil {
		return err
	} else if !found {
		return ErrResourceNotFound
	}

	return r.client.Sys().DisableAuth(path)
}

//
// ListAuths returns a list of auth backends
//
func (r vaultctl) ListAuths() ([]string, error) {
	var list []string
	auths, err := r.client.Sys().ListAuth()
	if err != nil {
		return list, err
	}

	for k, _ := range auths {
		list = append(list, k)
	}

	return list, nil
}

// IsValid validates the auth backend
func (r Auth) IsValid() error {
	if r.Type == "" {
		return fmt.Errorf("you must specify a auth type")
	}
	if r.Path == "" {
		return fmt.Errorf("you must specify a path")
	}
	if strings.HasSuffix(r.Path, "/") {
		return fmt.Errorf("path should not end with /")
	}
	if !containedIn(r.Type, SupportedAuthBackends) {
		return fmt.Errorf("auth type: %s is a unsupported auth type", r.Type)
	}

	for i, x := range r.Attrs {
		if err := x.IsValid(); err != nil {
			return fmt.Errorf("attribute %d invalid, error: %s", i, err)
		}
	}

	return nil
}
