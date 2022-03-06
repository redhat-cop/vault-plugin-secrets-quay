package quay

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const secretType = "quay_robot"

func secretRobot(b *quayBackend) *framework.Secret {
	return &framework.Secret{
		Type: secretType,
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeString,
				Description: "Quay robot account username",
			},
			"password": {
				Type:        framework.TypeString,
				Description: "Quay robot account username",
			},
		},
		Renew:  b.robotAccountRenew,
		Revoke: b.robotAccountRevoke,
	}

}

func pathCredentials(b *quayBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "creds/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role",
					Required:    true,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathCredentialsRead,
			},

			HelpSynopsis:    pathCredentialsHelpSyn,
			HelpDescription: pathCredentialsHelpDesc,
		},
		{
			Pattern: "static-creds/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role",
					Required:    true,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathStaticCredentialsRead,
			},

			HelpSynopsis:    pathStaticCredentialsHelpSyn,
			HelpDescription: pathStaticCredentialsHelpDesc,
		},
	}
}

func (b *quayBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("name is required"), nil
	}

	role, err := b.getRole(ctx, rolesStoragePath, roleName, req.Storage)
	if err != nil {
		return nil, err
	}
	if role == nil {
		// Attempting to read a role that doesn't exist.
		return nil, nil
	}

	lock := locksutil.LockForKey(b.roleLocks, roleName)
	lock.Lock()
	defer lock.Unlock()

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// Generate Robot Account Name
	randomRoleName := randomSuffix(roleName)

	robotAccount, err := b.createRobot(client, randomRoleName, role)

	if err != nil {
		return nil, err
	}

	secretData := map[string]interface{}{
		"namespace_type": role.NamespaceType,
		"namespace_name": role.NamespaceName,
		"username":       robotAccount.Name,
		"password":       robotAccount.Token,
	}
	secretInternalData := map[string]interface{}{
		"role":     roleName,
		"username": robotAccount.Name,
	}

	resp := b.Secret(secretType).Response(secretData, secretInternalData)

	resp.Secret.Renewable = true

	if role.TTL != 0 {
		resp.Secret.TTL = role.TTL
	}

	if role.MaxTTL != 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}

	return resp, nil

}

func (b *quayBackend) pathStaticCredentialsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("name is required"), nil
	}

	role, err := b.getRole(ctx, staticRolesStoragePath, roleName, req.Storage)
	if err != nil {
		return nil, err
	}
	if role == nil {
		// Attempting to read a role that doesn't exist.
		return nil, nil
	}

	lock := locksutil.LockForKey(b.roleLocks, roleName)
	lock.Lock()
	defer lock.Unlock()

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	robotAccount, err := b.createRobot(client, roleName, role)

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

func (b *quayBackend) robotAccountRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return logical.ErrorResponse("internal data 'role' not found"), nil
	}

	role, err := b.getRole(ctx, rolesStoragePath, roleRaw.(string), req.Storage)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return nil, nil
	}

	resp := &logical.Response{Secret: req.Secret}

	if role.TTL != 0 {
		resp.Secret.TTL = role.TTL
	}

	if role.MaxTTL != 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}

	return resp, nil
}

func (b *quayBackend) robotAccountRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	usernameRaw, ok := req.Secret.InternalData["username"]
	if !ok {
		return logical.ErrorResponse("internal data 'username' not found"), nil
	}

	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return logical.ErrorResponse("internal data 'role' not found"), nil
	}

	role, err := b.getRole(ctx, rolesStoragePath, roleRaw.(string), req.Storage)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return nil, nil
	}

	lock := locksutil.LockForKey(b.roleLocks, roleRaw.(string))
	lock.Lock()
	defer lock.Unlock()

	username := usernameRaw.(string)

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// Split out parts of robot account
	usernameSplit := strings.Split(username, "+")

	return nil, b.deleteRobot(client, usernameSplit[len(usernameSplit)-1], role)
}

func randomSuffix(input string) string {
	rand.Seed(time.Now().Unix())
	charSet := []rune("abcdefghijklmnopqrstuvqxyz")
	var output strings.Builder
	length := 5
	for i := 0; i < length; i++ {
		random := rand.Intn(len(charSet))
		randomChar := charSet[random]
		output.WriteRune(randomChar)
	}

	return fmt.Sprintf("%s-%s", input, output.String())

}

const pathCredentialsHelpSyn = "Generate the credential of the Quay robot account based on the associated Vault role."
const pathCredentialsHelpDesc = "Generate the credential of the Quay robot account based on the associated Vault role."
const pathStaticCredentialsHelpSyn = "Return the credential of the static Quay robot account based on the associated Vault role."
const pathStaticCredentialsHelpDesc = "Return the credential of the static Quay robot account based on the associated Vault role."
