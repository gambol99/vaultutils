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
	"time"
)

var (
	// ErrResourceNotFound indicates the resource acting upon was not found
	ErrResourceNotFound = errors.New("the resource does not exists")
	// ErrInvalidDefinition indicates the specification for the resource was incomplete or invalid
	ErrInvalidDefinition = errors.New("the resource specification is invalid")
)

var (
	// SupportedAuthBackends is a list of supported auth backend's
	SupportedAuthBackends = []string{"userpass", "ldap", "token", "appid", "github", "mfa", "tls"}
	// SupportedBackendTypes is a list of supported secret backend's
	SupportedBackendTypes = []string{
		"aws", "generic", "pki", "transit",
		"cassandra", "consul", "cubbyhole", "mysql",
		"postgres", "ssh", "custom",
	}
)

// Attributes is a map of configuration
type Attributes map[string]interface{}

// Config is the library configuration
type Config struct {
	// Verbose enable verbose logging
	Verbose bool
	// Hostname is the address of the vault service
	VaultHostname string
	// Credentials are the credentials to login
	Credentials Credentials
	// SkipTLSVerify indicates if we should skip verifying the TLS
	SkipTLSVerify bool
	// CertificateAuthority is a provider used to sign certificate
	CertificateAuthority *CertificateAuthority
}

//
// CertificateAuthority defines a cfssl signer
//
type CertificateAuthority struct {
	// Profile is used by multiroot ca
	Profile string `yaml:"profile"`
	// Token is the authentication token to use
	Token string `yaml:"token"`
	// URL is the url for signing requests
	URL string `yaml:"url"`
}

// Auth defined a authentication backend
type Auth struct {
	// Path is the path of the authentication backend
	Path string `yaml:"path" json:"path" hcl:"path"`
	// Type is the authentication type
	Type string `yaml:"type" json:"type" hcl:"type"`
	// Description is the a description for the backend
	Description string `yaml:"description" json:"description" hcl:"description"`
	// Attributes is a map of configurations for the backend
	Attrs []Attributes `yaml:"attributes" json:"attributes" hcl:"attributes"`
}

// Certificates holds the certificates
type Certificates struct {
	PrivateKey  string
	Certificate string
	CSR         string
}

// Backend defined the type and configuration for a backend in vault
type Backend struct {
	// Path is the mountpoint for the mount
	Path string `yaml:"path" json:"path" hcl:"path"`
	// Description is the a description for the backend
	Description string `yaml:"description" json:"description" hcl:"description"`
	// Type is the type of backend
	Type string `yaml:"type" json:"type" hcl:"type"`
	// DefaultLeaseTTL is the default lease of the backend
	DefaultLeaseTTL time.Duration `yaml:"default-lease-ttl" json:"default-lease-ttl" hcl:"default-lease-ttl"`
	// MaxLeaseTTL is the max ttl
	MaxLeaseTTL time.Duration `yaml:"max-lease-ttl" json:"max-lease-ttl" hcl:"max-lease-ttl"`
	// Attrs is the configuration of the mount point
	Attrs []Attributes `yaml:"attributes" json:"attributes" hcl:"attributes"`
}

// Policy defines a vault policy
type Policy struct {
	// Name is the name of the policy
	Name string `yaml:"name" json:"name" hcl:"name"`
	// Path is a series of paths and their permissions
	Path map[string]PolicyPermission `yaml:"path" json:"path" hcl:"path"`
}

// PolicyPermission represents a path permission
type PolicyPermission struct {
	// Policy is the permission
	Policy string `yaml:"policy" json:"policy" hcl:"policy"`
	// Capabilities
	Capabilities []string `yaml:"capabilities,omitempty" json:"capabilities,omitempty" hcl:"capabilities,omitempty"`
}

// Secret defines a secret
type Secret struct {
	// Path is key for this secret
	Path string `yaml:"path" json:"path" hcl:"path"`
	// Values is a series of values associated to the secret
	Values Attributes `yaml:"values" json:"values" hcl:"values"`
}

// Credentials are credentials to login into vault
type Credentials struct {
	// Path is the path of the auth backend
	Path string `yaml:"path" json:"path" hcl:"path"`
	// UserPass is the credentials for a userpass auth backend
	UserPass *UserPass `yaml:"userpass" json:"userpass" hcl:"userpass"`
	// UserToken is a token struct for this user
	UserToken *string `yaml:"usertoken" json:"usertoken" hcl:"usertoken"`
}

// User is the definition for a user
type User struct {
	// Path is the authentication path for the user
	Path string `yaml:"path" json:"path" hcl:"path"`
	// UserPass is the credentials for a userpass auth backend
	UserPass *UserPass `yaml:"userpass" json:"userpass" hcl:"userpass"`
	// UserToken is a token struct for this user
	UserToken *UserToken `yaml:"usertoken" json:"usertoken" hcl:"usertoken"`
	// Policies is a list of policies the user has access to
	Policies []string `yaml:"policies,omitempty" json:"policies,omitempty" hcl:"policies,omitempty"`
}

// UserPass are the userpass credentials
type UserPass struct {
	// Username is the id of the user
	Username string `yaml:"username" json:"username" hcl:"username"`
	// Password is the password of the user
	Password string `yaml:"password" json:"password" hcl:"password"`
}

// UserToken is the token
type UserToken struct {
	// Path is the path of the auth token backend
	Path string `yaml:"path" json:"path" hcl:"path"`
	// ID is the actual token itself
	ID string `yaml:"id" json:"id" hcl:"id"`
	// TTL is the time duration of the token
	TTL time.Duration `yaml:"ttl" json:"ttp" hcl:"ttl"`
	// DisplayName is a generic name for the token
	DisplayName string `yaml:"display-name" json:"display-name" hcl:"display-name"`
	// MaxUses is the max number of times the token can be used
	MaxUses int `yaml:"max-uses" json:"max-uses" hcl:"max-uses"`
	// Policies is a list of polices for the token
	Policies []string `yaml:"policies,omitempty" json:"policies,omitempty" hcl:"policies,omitempty"`
	// Metadata is metadata for the token
	Metadata map[string]string `yaml:"metadata" json:"metadata" hcl:"metadata"`
}

type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}
