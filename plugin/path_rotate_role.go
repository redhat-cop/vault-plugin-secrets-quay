package quay

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRotateRole(b *quayBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "rotate-role/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role",
					Required:    true,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRotateRole,
			},

			HelpSynopsis:    pathRotateRoleHelpSynopsis,
			HelpDescription: pathRotateRoleHelpDescription,
		},
	}
}

func (b *quayBackend) pathRotateRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("name is required"), nil
	}

	role, err := b.getRole(ctx, staticRolesStoragePath, roleName, req.Storage)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return logical.ErrorResponse("No Static Role Found"), nil
	}

	lock := locksutil.LockForKey(b.roleLocks, roleName)
	lock.Lock()
	defer lock.Unlock()

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	robotAccount, err := b.regenerateRobotPassword(client, roleName, role)

	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"namespace_type":  role.NamespaceType,
			"namespaces_name": role.NamespaceName,
			"username":        robotAccount.Name,
			"password":        robotAccount.Token,
		},
	}, nil

}

const pathRotateRoleHelpSynopsis = `Rotates the credential for a static role mapped to a Quay Robot Account.`
const pathRotateRoleHelpDescription = "This path allows you to regenerate the credentials used by a static role mapped to a Quay Robot Account"
