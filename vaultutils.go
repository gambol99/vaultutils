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
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
)

const (
	apiVersion = "v1"
)

type vaultctl struct {
	client *api.Client
}

//
// NewClient creates a new vaultutils client
//
func NewClient(config Config) (Client, error) {
	options := api.DefaultConfig()
	options.Address = config.VaultHostname
	options.HttpClient = &http.Client{
		Timeout: time.Duration(10) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: config.SkipTLSVerify,
			},
		},
	}
	// step: get the client
	client, err := api.NewClient(options)
	if err != nil {
		return nil, err
	}

	// step: attempt to login and retrieve a token
	token, err := authorizeClient(client, config.Credentials)
	if err != nil {
		return nil, err
	}
	client.SetToken(token)

	return &vaultctl{
		client: client,
	}, nil
}

//
// authorizeClient attempts to login to vault to retrieve a token
//
func authorizeClient(client *api.Client, creds Credentials) (string, error) {
	// step: just hand back the token
	if creds.UserToken != nil {
		return *creds.UserToken, nil
	}
	// step: we need to login to the service
	if creds.UserPass != nil {
		var password struct {
			Password string `json:"password"`
		}
		password.Password = creds.UserPass.Password

		// step: create the token request
		request := client.NewRequest("POST", fmt.Sprintf("/v1/%s/login/%s", creds.Path, creds.UserPass.Username))
		if err := request.SetJSONBody(password); err != nil {
			return "", err
		}
		// step: make the request
		resp, err := client.RawRequest(request)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		secret, err := api.ParseSecret(resp.Body)
		if err != nil {
			return "", err
		}

		return secret.Auth.ClientToken, nil
	}

	return "", ErrNoAuthentication
}

//
// request performs a raw authenticated request to the vault service
//
func (r vaultctl) request(method, uri string, body interface{}) (*http.Response, error) {
	url := fmt.Sprintf("/%s/%s", apiVersion, strings.TrimPrefix(uri, "/"))

	request := r.client.NewRequest(method, url)
	if err := request.SetJSONBody(body); err != nil {
		return nil, err
	}
	// step: make the request
	resp, err := r.client.RawRequest(request)
	if err != nil {
		return nil, err
	}

	return resp.Response, nil
}
