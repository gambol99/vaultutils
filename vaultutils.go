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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/api/client"
	"github.com/cloudflare/cfssl/auth"
	"github.com/hashicorp/vault/api"
)

const (
	apiVersion = "v1"
)

type vaultctl struct {
	// the vault client
	client *api.Client
	// the signing client
	signer *client.AuthRemote
	// the config
	config *Config
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
	vc, err := api.NewClient(options)
	if err != nil {
		return nil, err
	}

	// step: attempt to login and retrieve a token
	token, err := authorizeClient(vc, config.Credentials)
	if err != nil {
		return nil, err
	}
	vc.SetToken(token)

	// step: create a signer if required
	var signer *client.AuthRemote
	if config.CertificateAuthority != nil {
		sig, err := auth.New(config.CertificateAuthority.Token, []byte{})
		if err != nil {
			return nil, err
		}
		signer = client.NewAuthServer(config.CertificateAuthority.URL, sig)
	}

	return &vaultctl{
		client: vc,
		signer: signer,
		config: &config,
	}, nil
}

func (r *vaultctl) RawClient() *api.Client {
	return r.client
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
func (r vaultctl) request(method, uri string, body interface{}) (*api.Secret, error) {
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
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 399 {
		return nil, fmt.Errorf("invalid response from vault, content: %s", resp.Body)
	}

	var secret *api.Secret
	if resp.ContentLength > 0 || resp.ContentLength < 0 {
		// step: decode the response into a secret
		secret = new(api.Secret)
		if err := json.NewDecoder(resp.Body).Decode(secret); err != nil {
			return nil, err
		}
	}

	return secret, nil
}
