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
	"errors"
)

var (
	// ErrNoAuthentication indicates no authentication method was given
	ErrNoAuthentication = errors.New("no authentication specified")
)

// Client is the interface
type Client interface {
	// MountAuth creates or updates a auth backend
	MountAuth(Auth) (bool, error)
	// MountBackend creates or update a secrets backend
	MountBackend(Backend) (bool, error)
	// HasBackend check if the backend exists
	HasBackend(string) (bool, error)
	// HasAuth checks if the authentication backend exists
	HasAuth(string) (bool, error)
	// HasPolicy checks if the policy exists
	HasPolicy(string) (bool, error)
	// AddGenericSecrets adds a generic secret
	AddGenericSecrets(string, map[string]string) error
	// RemoveGenericSecret remove a secret
	RemoveGenericSecret(string) error
	// SetPolicy adds or updates a policy
	SetPolicy(Policy) (bool, error)
	// GetPolicy retrieves a policy
	GetPolicy(string) (Policy, error)
	// DeletePolicy remove a policy
	DeletePolicy(string) error
	// DeleteAuthBackend removes the auth backend
	DeleteAuth(string) error
	// DeleteBackend removes the backend
	DeleteBackend(string) error
	// ListMounts retrieves a list of mounted backends
	ListMounts() ([]string, error)
	// ListPolicies get a list of policies
	ListPolicies() ([]string, error)
	// ListGenericSecrets lists all the secrets under a path
	ListGenericSecrets(string) ([]string, error)
	// ListAuths returns a list of auth backend
	ListAuths() ([]string, error)
}
