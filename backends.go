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

	"github.com/hashicorp/vault/api"
)

//
// MountBackend creates or update a secrets backend
//
func (r vaultctl) MountBackend(b Backend) error {
	if err := b.IsValid(); err != nil {
		return err
	}
	// step: check if the backend exists
	found, err := r.HasBackend(b.Path)
	if err != nil {
		return err
	}
	if !found {
		if err := r.client.Sys().Mount(b.Path, &api.MountInput{
			Type:        b.Type,
			Description: b.Description,
			Config: api.MountConfigInput{
				DefaultLeaseTTL: b.DefaultLeaseTTL.String(),
				MaxLeaseTTL:     b.MaxLeaseTTL.String(),
			},
		}); err != nil {
			return err
		}
		found = false
	}

	// step: configure the backend
	for _, c := range b.Attrs {
		// step: check if a once type setting?
		if found && c.IsOneshot() {
			continue
		}
		resp, err := r.request("PUT", c.GetPath(b.Path), &c)
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
// DeleteBackend removes the backend
//
func (r vaultctl) DeleteBackend(path string) error {
	if found, err := r.HasBackend(path); err != nil {
		return err
	} else if !found {
		return ErrResourceNotFound
	}

	return r.client.Sys().Unmount(path)
}

//
// ListMounts retrieves a list of mounted backends
//
func (r vaultctl) ListMounts() ([]string, error) {
	var list []string

	mounts, err := r.client.Sys().ListMounts()
	if err != nil {
		return list, err
	}
	for k, _ := range mounts {
		list = append(list, k)
	}

	return list, nil
}

//
// HasBackend check if the backend exists
//
func (r vaultctl) HasBackend(path string) (bool, error) {
	mounts, err := r.ListMounts()
	if err != nil {
		return false, err
	}

	return containedIn(path, mounts), nil
}

// IsValid validates the backend is ok
func (r Backend) IsValid() error {
	if r.Path == "" {
		return fmt.Errorf("backend must have a path")
	}
	if r.Type == "" {
		return fmt.Errorf("backend %s must have a type", r.Path)
	}
	if r.Description == "" {
		return fmt.Errorf("backend %s must have a description", r.Path)
	}
	if r.MaxLeaseTTL.Seconds() < r.DefaultLeaseTTL.Seconds() {
		return fmt.Errorf("backend: %s, max lease ttl cannot be less than the default", r.Path)
	}
	if r.DefaultLeaseTTL.Seconds() < 0 {
		return fmt.Errorf("backend: %s, default lease time must be positive", r.Path)
	}
	if r.MaxLeaseTTL.Seconds() < 0 {
		return fmt.Errorf("backend: %s, max lease time must be positive", r.Path)
	}
	if !containedIn(r.Type, SupportedBackendTypes) {
		return fmt.Errorf("backend: %s, unsupported type: %s", r.Path, r.Type)
	}
	if r.Attrs != nil && len(r.Attrs) > 0 {
		for _, x := range r.Attrs {
			// step: ensure the config has a uri
			if x.URI() == "" {
				return fmt.Errorf("backend: %s, config for must have uri", r.Path)
			}
		}
	}

	return nil
}
