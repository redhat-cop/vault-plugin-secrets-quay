package quay

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
)

type Permission string
type TeamRole string
type AccountType string

const (
	rolesStoragePath                    = "roles"
	staticRolesStoragePath              = "static-roles"
	organization                        = "organization"
	TeamRoleAdmin           TeamRole    = "admin"
	TeamRoleCreator         TeamRole    = "creator"
	TeamRoleMember          TeamRole    = "member"
	AccountTypeUser         AccountType = "user"
	AccountTypeOrganization AccountType = "organization"
	PermissionAdmin         Permission  = "admin"
	PermissionRead          Permission  = "read"
	PermissionWrite         Permission  = "write"
)

type quayRoleEntry struct {
	AccountType        AccountType            `json:"account_type"`
	AccountName        string                 `json:"account_name"`
	CreateRepositories bool                   `json:"create_repositories,omitempty"`
	DefaultPermission  *Permission            `json:"default_permission,omitempty"`
	Teams              *map[string]TeamRole   `json:"teams,omitempty"`
	Repositories       *map[string]Permission `json:"repositories,omitempty"`
	TTL                time.Duration          `json:"ttl,omitempty"`
	MaxTTL             time.Duration          `json:"max_ttl,omitempty"`
}

type quayPermission struct {
	Name       string     `json:"name"`
	Permission Permission `json:"permission"`
}

func pathRole(b *quayBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: fmt.Sprintf("%s/%s", rolesStoragePath, framework.GenericNameRegex("name")),
			Fields:  dynamicRoleFieldSchemas(),
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRolesRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRolesDelete,
				},
			},
			ExistenceCheck:  b.pathRoleExistenceCheck,
			HelpSynopsis:    pathRoleHelpSynopsis,
			HelpDescription: pathRoleHelpDescription,
		},
		{
			Pattern: fmt.Sprintf("%s/%s", staticRolesStoragePath, framework.GenericNameRegex("name")),
			Fields:  defaultFieldSchemas(),
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRolesRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRolesDelete,
				},
			},
			ExistenceCheck:  b.pathRoleExistenceCheck,
			HelpSynopsis:    pathStaticRoleHelpSynopsis,
			HelpDescription: pathStaticRoleHelpDescription,
		},
		{
			Pattern: fmt.Sprintf("(%s|%s)/?$", rolesStoragePath, staticRolesStoragePath),

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRolesList,
				},
			},

			HelpSynopsis:    pathRoleListHelpSynopsis,
			HelpDescription: pathRoleListHelpDescription,
		},
	}
}

func (b *quayBackend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := b.getRole(ctx, getStoragePath(req), data.Get("name").(string), req.Storage)
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *quayBackend) pathRolesList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	path := rolesStoragePath
	if strings.HasPrefix(req.Path, staticRolesStoragePath) {
		path = staticRolesStoragePath
	}
	entries, err := req.Storage.List(ctx, fmt.Sprintf("%s/", path))
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

// pathRolesRead makes a request to Vault storage to read a role and return response data
func (b *quayBackend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	storagePath := getStoragePath(req)
	entry, err := b.getRole(ctx, storagePath, d.Get("name").(string), req.Storage)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	respData := map[string]interface{}{
		"account_name":        entry.AccountName,
		"account_type":        entry.AccountType,
		"create_repositories": entry.CreateRepositories,
	}

	if entry.DefaultPermission != nil {
		respData["default_permission"] = entry.DefaultPermission.String()
	}

	if entry.Repositories != nil {
		respData["repositories"] = entry.Repositories
	}

	if storagePath == rolesStoragePath {
		respData["ttl"] = entry.TTL.Seconds()
		respData["max_ttl"] = entry.MaxTTL.Seconds()
	}

	return &logical.Response{
		Data: respData,
	}, nil
}

func (b *quayBackend) pathRolesWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("name is required"), nil
	}

	roleEntry, err := b.getRole(ctx, getStoragePath(req), roleName, req.Storage)
	if err != nil {
		return nil, err
	}
	if roleEntry == nil && req.Operation == logical.UpdateOperation {
		return nil, fmt.Errorf("no role found to update for %s", roleName)
	} else if roleEntry == nil {
		roleEntry = &quayRoleEntry{}
	}

	accountType := data.Get("account_type")
	roleEntry.AccountType = AccountType(accountType.(string))

	if accountName, ok := data.GetOk("account_name"); ok {
		roleEntry.AccountName = accountName.(string)
	}

	if createRepositoriesRaw, ok := data.GetOk("create_repositories"); ok {
		roleEntry.CreateRepositories = createRepositoriesRaw.(bool)
	}

	if defaultPermissionRaw, ok := data.GetOk("default_permission"); ok {
		defaultPermission := Permission(defaultPermissionRaw.(string))
		roleEntry.DefaultPermission = &defaultPermission
	}

	if repositoriesRaw, ok := data.GetOk("repositories"); ok {
		parsedRepositories := make(map[string]Permission, 0)
		err := jsonutil.DecodeJSON([]byte(repositoriesRaw.(string)), &parsedRepositories)
		if err != nil {
			return logical.ErrorResponse("error parsing repositories '%s': %s", repositoriesRaw.(string), err.Error()), nil
		}
		roleEntry.Repositories = &parsedRepositories
	}

	if ttlRaw, ok := data.GetOk("ttl"); ok {
		roleEntry.TTL = time.Duration(ttlRaw.(int)) * time.Second
	}

	if maxTTLRaw, ok := data.GetOk("max_ttl"); ok {
		roleEntry.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	}

	if roleEntry.MaxTTL != 0 && roleEntry.TTL > roleEntry.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	if err := b.saveRole(ctx, req.Storage, roleEntry, getStoragePath(req), roleName); err != nil {
		return nil, err
	}

	return nil, nil

}

func (b *quayBackend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	storagePath := getStoragePath(req)

	// Delete Robot Account if static role
	if storagePath == staticRolesStoragePath {

		roleEntry, err := b.getRole(ctx, storagePath, name, req.Storage)

		if err != nil {
			return nil, err
		}

		if roleEntry == nil {
			return nil, nil
		}

		client, err := b.getClient(ctx, req.Storage)
		if err != nil {
			return nil, err
		}

		err = b.DeleteRobot(client, name, roleEntry)

		if err != nil {
			return nil, err
		}
	}

	err := req.Storage.Delete(ctx, fmt.Sprintf("%s/%s", getStoragePath(req), name))
	if err != nil {
		return nil, fmt.Errorf("error deleting role: %w", err)
	}

	return nil, nil
}

func (b *quayBackend) saveRole(ctx context.Context, s logical.Storage, roleEntry *quayRoleEntry, storagePath string, name string) error {
	entry, err := logical.StorageEntryJSON(fmt.Sprintf("%s/%s", storagePath, name), roleEntry)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

func (b *quayBackend) getRole(ctx context.Context, storagePath string, name string, s logical.Storage) (*quayRoleEntry, error) {
	entry, err := s.Get(ctx, fmt.Sprintf("%s/%s", storagePath, name))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	role := new(quayRoleEntry)
	if err := entry.DecodeJSON(role); err != nil {
		return nil, err
	}
	return role, nil
}

func getStoragePath(req *logical.Request) string {
	storagePath := rolesStoragePath
	if strings.HasPrefix(req.Path, staticRolesStoragePath) {
		storagePath = staticRolesStoragePath
	}

	return storagePath

}

func defaultFieldSchemas() map[string]*framework.FieldSchema {

	return map[string]*framework.FieldSchema{
		"name": {
			Type:        framework.TypeLowerCaseString,
			Description: "Name of the role",
			Required:    true,
			DisplayAttrs: &framework.DisplayAttributes{
				Name: "Name",
			},
		},
		"account_name": {
			Type:        framework.TypeString,
			Description: "Type of account the robot account should be placed within",
			Required:    true,
			DisplayAttrs: &framework.DisplayAttributes{
				Name: "Robot Account Name",
			},
		},
		"account_type": {
			Type:          framework.TypeString,
			Description:   "Type of account the robot account should be placed within",
			AllowedValues: []interface{}{"user", "organization"},
			Default:       "organization",
			Required:      true,
			DisplayAttrs: &framework.DisplayAttributes{
				Name: "Account Type",
			},
		},
		"create_repositories": {
			Type:        framework.TypeBool,
			Description: "Allow the Robot Account to create repositories in the organization",
			DisplayAttrs: &framework.DisplayAttributes{
				Name: "Create Repositories",
			},
		},
		"default_permission": {
			Type:          framework.TypeString,
			Description:   "Default permission applied to new repositories",
			AllowedValues: []interface{}{"admin", "read", "write"},
			DisplayAttrs: &framework.DisplayAttributes{
				Name: "Default Permission",
			},
		},
		"repositories": {
			Type:        framework.TypeString,
			Description: "Permissions to apply to repositories",
			DisplayAttrs: &framework.DisplayAttributes{
				Name: "Repositories",
			},
		},
	}

}

func dynamicRoleFieldSchemas() map[string]*framework.FieldSchema {
	dynamicRoleFieldSchemas := defaultFieldSchemas()

	dynamicRoleFieldSchemas["ttl"] = &framework.FieldSchema{
		Type:        framework.TypeDurationSecond,
		Description: "Default lease for generated credentials. If not set or set to 0, will use system default.",
	}

	dynamicRoleFieldSchemas["max_ttl"] = &framework.FieldSchema{
		Type:        framework.TypeDurationSecond,
		Description: "Maximum time for role. If not set or set to 0, will use system default.",
	}

	return dynamicRoleFieldSchemas
}

func (a *AccountType) String() string {
	return string(*a)
}

func (p *Permission) String() string {
	return string(*p)
}

const pathRoleHelpSynopsis = `Manages the Vault role for generating Quay robot accounts.`
const pathRoleHelpDescription = "This path allows you to read and write roles used to generate Quay robot accounts."
const pathStaticRoleHelpSynopsis = `Manages the Vault role for generating static Quay robot accounts.`
const pathStaticRoleHelpDescription = "This path allows you to read and write roles used to generate static Quay robot accounts."
const pathRoleListHelpSynopsis = `List existing roles.`
const pathRoleListHelpDescription = `List existing roles by name.`
