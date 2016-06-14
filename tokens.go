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
	"time"

	"github.com/hashicorp/vault/api"
)

//
// CreateToken creates a new user token
//
func (r vaultctl) CreateToken(u UserToken) (string, error) {
	secret, err := r.client.Auth().Token().Create(&api.TokenCreateRequest{
		ID:          u.ID,
		Policies:    u.Policies,
		TTL:         u.TTL.String(),
		DisplayName: u.DisplayName,
		NumUses:     u.MaxUses,
		Metadata:    u.Metadata,
	})
	if err != nil {
		return "", err
	}

	return secret.Auth.ClientToken, nil
}

//
// LookupToken checks for a token
//
func (r vaultctl) LookupToken(token string) (UserToken, error) {
	secret, err := r.client.Auth().Token().Lookup(token)
	if err != nil {
		return UserToken{}, err
	}
	user := UserToken{}
	if v, found := secret.Data["id"]; found {
		user.ID = v.(string)
	}
	if v, found := secret.Data["display_name"]; found {
		user.DisplayName = v.(string)
	}
	if v, found := secret.Data["ttl"]; found {
		f := v.(float64)
		user.TTL = time.Duration(int64(f))
	}
	if v, found := secret.Data["policies"]; found {
		for _, x := range v.([]interface{}) {
			user.Policies = append(user.Policies, fmt.Sprintf("%v", x))
		}
	}
	if v, found := secret.Data["meta"]; found {
		if v != nil {
			for k, v := range v.(map[interface{}]interface{}) {
				user.Metadata[k.(string)] = v.(string)
			}
		}
	}

	return user, nil
}

//
// IsValid checks the defition is valid
//
func (r UserToken) IsValid() error {
	if r.DisplayName == "" {
		return fmt.Errorf("no display name")
	}
	if r.Path == "" {
		return fmt.Errorf("no path")
	}

	return nil
}
