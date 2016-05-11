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
	"encoding/json"
)

//
// HasPolicy check if the policy exists
//
func (r vaultctl) HasPolicy(name string) (bool, error) {
	list, err := r.Policies()
	if err != nil {
		return false, err
	}

	return containedIn(name, list), nil
}

//
// Policies is a list of policies currently in vault
//
func (r vaultctl) Policies() ([]string, error) {
	var list []string

	policies, err := r.client.Sys().ListPolicies()
	if err != nil {
		return list, err
	}
	for _, k := range policies {
		list = append(list, k)
	}

	return list, nil
}

//
// GetPolicy retrieves a policy
//
func (r vaultctl) GetPolicy(name string) (Policy, error) {
	var policy Policy

	if found, err := r.HasPolicy(name); err != nil {
		return Policy{}, err
	} else if !found {
		return Policy{}, ErrResourceNotFound
	}
	content, err := r.client.Sys().GetPolicy(name)
	if err != nil {
		return Policy{}, err
	}
	policy.Name = name

	if err := json.Unmarshal([]byte(content), &policy); err != nil {
		return Policy{}, err
	}

	return policy, nil
}

//
// Delete Policy remove a policy from vault
//
func (r vaultctl) DeletePolicy(name string) error {
	if found, err := r.HasPolicy(name); err != nil {
		return err
	} else if !found {
		return ErrResourceNotFound
	}

	return r.client.Sys().DeletePolicy(name)
}

//
// SetPolicy sets a policy in vault
//
func (r vaultctl) SetPolicy(policy Policy) (bool, error) {
	var p struct {
		Path map[string]PolicyPermission `yaml:"path" json:"path" hcl:"path"`
	}
	if len(policy.Path) <= 0 {
		p.Path = make(map[string]PolicyPermission, 0)
	} else {
		p.Path = policy.Path
	}

	// step: check if a policy exists already
	found, err := r.HasPolicy(policy.Name)
	if err != nil {
		return false, err
	}
	// step: encode the policy into json
	content, err := json.Marshal(&p)
	if err != nil {
		return false, err
	}

	if err := r.client.Sys().PutPolicy(policy.Name, string(content)); err != nil {
		return false, err
	}

	return !found, nil
}

//
// ListPolicies get a list of policies
//
func (r vaultctl) ListPolicies() ([]string, error) {
	return r.client.Sys().ListPolicies()
}

//
// Clone returns a copy of the policy
//
func (r Policy) Clone() Policy {
	p := Policy{
		Name: r.Name,
	}
	for k, v := range p.Path {
		p.Path[k] = v
	}

	return p
}
