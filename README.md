# Vault Plugin: Quay Secrets Backend

**NOTE: This plugin is still in active development and functionality is expected to change frequently**

This is a standalone backend plugin for use with [Hashicorp Vault](https://www.github.com/hashicorp/vault).

This plugin manages the lifecycle of Quay Robot accounts within an organization or associated with a user. Robot accounts can be created using long lived credentials or short lived, [Dynamic Secrets](https://learn.hashicorp.com/tutorials/vault/getting-started-dynamic-secrets).

Additional information can be found in the [Getting Started](#getting-started) and [Usage](#usage) sections.

**Please note**: We take Vault's security and our users' trust very seriously. If you believe you have found a security issue in Vault, _please responsibly disclose_ by contacting us at [security@hashicorp.com](mailto:security@hashicorp.com).

## Quick Links

- [Vault Website](https://www.vaultproject.io)
- [Quay Website](https://quay.io)
- [Vault Github Project](https://www.github.com/hashicorp/vault)

## Getting Started

This is a [Vault plugin](https://www.vaultproject.io/docs/internals/plugins.html)
and is meant to work with Vault. This guide assumes you have already installed Vault
and have a basic understanding of how Vault works.

Otherwise, first read this guide on how to [get started with Vault](https://www.vaultproject.io/intro/getting-started/install.html).

To learn specifically about how plugins work, see documentation on [Vault plugins](https://www.vaultproject.io/docs/internals/plugins.html).

## Developing

If you wish to work on this plugin, you'll first need
[Go](https://www.golang.org) installed on your machine
(version 1.17+ is _required_).

For local dev first make sure Go is properly installed, including
setting up a [GOPATH](https://golang.org/doc/code.html#GOPATH).
Next, clone this repository into
`$GOPATH/src/github.com/redhat-cop/vault-plugin-secrets-quay`.

To compile the plugin, run `make build`

This will put the plugin binary in the `vault/plugins` directory:

```shell
make build
```

Once the binary has been built, you can start a Vault development server:

```shell
$ vault start
...
```

Once the server is started, the plugin will be registered in the Vault [plugin catalog](https://www.vaultproject.io/docs/internals/plugins.html#plugin-catalog).

The plugin can be enabled by running the following command:

```shell
$ make enable

vault secrets enable -path=quay vault-plugin-secrets-quay
```

# Usage

Register a new _config_ by providing the endpoint to the Quay instance and OAUth token for the API. More information on how to generate an OAuth token can be found [here](https://docs.quay.io/api/).

```shell
vault write quay/config \
  url=https://<QUAY_URL> \
  token=<TOKEN>
```

Two different types of [roles](https://learn.hashicorp.com/tutorials/vault/custom-secrets-engine-role) can be configured:

- Static Roles (`static-roles`) - Provides long lived credentials to access Quay
- Dynamic (`roles`) - Provides short lived, temporary credentials with a TTL expiration

Let's show examples of how each can be used.

## Static Roles

To manage repositories within the _myorg_ organization and assuming the OAuth token configured previously has the permissions to manage these resources, create a static role which will have permission to create repositories:

```shell
$ vault write quay/static-roles/my-static-account \
  account_name=myorg \
  account_type=organization \
  create_repositories=true
```

Credentials for the robot account can be obtained by executing the following command:

```shell
$ vault read quay/static-creds/my-static-account

Key             Value
---             -----
account_name    myorg
account_type    organization
password        <PASSWORD>
username        <USERNAME>
```

A new robot account will be created in the _myorg_ organization with _creator_ permissions. These credentials will not expire.

To remove the robot account and revoke credentials, execute the following command:

```shell
vault delete quay/static-roles/my-static-account
```

## Dynamic Secrets

Short lived credentials can be created to limit validity of a robot account. Similar to static roles, a role that leverages the dynamic secrets engine can be created using the following command:

```shell
$ vault write quay/roles/my-dynamic-account \
  account_name=myorg \
  account_type=organization \
  create_repositories=true
```

By default, the the default _ttl_ as configured in vault when a credential is requested. Otherwise a custom ttl can be specified using the `ttl=<value>` in the `vault write` command.

Dynamically generated credentials for a robot account can be obtained by executing the following command:

```shell
$ vault read quay/creds/my-dynamic-account

Key                Value
---                -----
lease_id           quay/creds/my-dynamic-account/JVrcAL9Oyrat2MOgKKTdrL1T
lease_duration     100h
lease_renewable    true
account_name       myorg
account_type       organization
password           <PASSWORD>
username           <USERNAME_WITH_UNIQUE_SUFFIX>
```

A robot account with a dynamically generated name will be created within the _myorg_ organization with permissions to create repositories and contain a unique username suffix.

The _lease_duration_property illustrates how long the credential can be used for. Once this value expires, the robot account will be deleted from Quay. The lease can be extended using the `vault lease renew` command. The `vault lease revoke` command can be used to revoke the active lease and delete the robot account.

The role itself can be removed using the following command:

```shell
vault delete quay/roles/my-dynamic-account
```
