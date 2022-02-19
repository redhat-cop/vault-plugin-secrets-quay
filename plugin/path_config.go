package quay

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStoragePath = "config"
)

type quayConfig struct {
	URL                    string `json:"url"`
	Token                  string `json:"token"`
	CaCertificate          string `json:"ca_certificate"`
	DisableSslVerification bool   `json:"disable_ssl_verification"`
}

func pathConfig(b *quayBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"url": {
				Type:     framework.TypeString,
				Required: true,
				Default:  "https://quay.io",
				Description: `The URL of the Quay server.
				Default is "https://quay.io"`,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Quay URL",
				},
			},
			"token": {
				Type:        framework.TypeString,
				Required:    true,
				Description: "Token to authenticate against Quay.",
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Token",
					Sensitive: true,
				},
			},
			"ca_certificate": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Certificate for the Quay server",
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "CA Certificate",
				},
			},
			"disable_ssl_verification": &framework.FieldSchema{
				Type:        framework.TypeBool,
				Default:     false,
				Description: "Disable SSL verification",
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Disable SSL verification",
				},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
			},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    pathConfigHelpSynopsis,
		HelpDescription: pathConfigHelpDescription,
	}
}

func (b *quayBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

func (b *quayBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"url":                      config.URL,
			"ca_certificate":           config.CaCertificate,
			"disable_ssl_verification": config.DisableSslVerification,
		},
	}, nil
}

func (b *quayBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	createOperation := (req.Operation == logical.CreateOperation)

	if config == nil {
		if !createOperation {
			return logical.ErrorResponse("config not found during update operation"), nil
		}
		config = new(quayConfig)
	}

	if url, ok := data.GetOk("url"); ok {
		config.URL = url.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing url in configuration")
	}

	token, ok := data.GetOk("token")
	if ok {
		config.Token = token.(string)
	}

	caCertificate, ok := data.GetOk("ca_certificate")
	if ok {
		config.CaCertificate = caCertificate.(string)
	}

	disableSslVerification, ok := data.GetOk("disable_ssl_verification")
	if ok {
		config.DisableSslVerification = disableSslVerification.(bool)
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.reset()

	return nil, nil
}

func (b *quayBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, configStoragePath)

	if err == nil {
		b.reset()
	}

	return nil, err
}

func getConfig(ctx context.Context, s logical.Storage) (*quayConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := new(quayConfig)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading root configuration: %w", err)
	}

	return config, nil
}

const pathConfigHelpSynopsis = `Configure the Quay backend.`

const pathConfigHelpDescription = `
The Quay secret backend requires credentials for managing
robot accounts associated within an organization on an instance of Quay. This endpoint
is used to configure those credentials.
`
