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

## Installation

The plugin can be installed by either downloading a release or building from source for your desired Operating System and architecture

### Release

Download the latest stable version from the [Releases](https://github.com/sabre1041/vault-plugin-secrets-quay/blob/main/releases) page.

### From Source

Instructions on how to build the plugin manually can be found in the [Developing](#developing) section.

### Plugin installation

Custom Vault plugins require additional steps before they can be made available to Vault.

1. Move the plugin binary to the `plugin_directory` as configured in Vault:

```shell
mv vault-plugin-secrets-quay-<os>-<arch> <plugin_directory>/vault-plugin-secrets-quay
```

2. Calculate the plugin binary SHA256 sum. Set an environment variable called _SHA256SUM_ either using the release binary or from source.

```shell
# Using compiled binary using checksums.txt from Release
SHA256SUM=$(grep <binary_name>$ checksums.txt | cut -d' ' -f1)
# Built from source
SHA256SUM=$(shasum -a 256 <compiled_binary> | cut -d' ' -f1)
```

3. Register the plugin in Vault

```shell
vault plugin register -sha256=$SHA256SUM vault-plugin-secrets-quay
```

4. Enable the plugin

```shell
vault secrets enable quay
```

## Configuration and Usage

This section describes how to configure and use the secrets engine.

### Configuration

Register a new _config_ by providing the endpoint to the Quay instance and OAUth token for the API. More information on how to generate an OAuth token can be found [here](https://docs.quay.io/api/).

```shell
vault write quay/config \
  url=https://<QUAY_URL> \
  token=<TOKEN>
```

The full list of options can be found below:

| Name | Description | Defaults | Required |
| ----- | ---------- | -------- | ----- |
| `url` | URL of the Quay instance | | Yes |
| `token` | Quay OAuth token | | Yes |
| `ca_certificate` | CA certificate to communicate to | | No |
| `disable_ssl_verification` | Disable SSL verification when communicating with Quay | | No |

### Roles

Two different types of [roles](https://learn.hashicorp.com/tutorials/vault/custom-secrets-engine-role) can be configured:

- Static Roles (`static-roles`) - Provides long lived credentials to access Quay
- Dynamic (`roles`) - Provides short lived, temporary credentials with a TTL expiration

A new _static role_ is created at the endpoint `quay/static-roles` while dynamic roles are created against the endpoint `quay/roles`.

The full list of options when configuring roles can be found below:

| Name | Description | Defaults | Required |
| ----- | ---------- | -------- | ----- |
| `namespace_type` | Type of namespace to associate the Robot account to (`user` or `organization`) | `organization` | No |
| `namespace_name` | Name of the _user_ or _organization_ the Robot account should be created within | | Yes |
| `create_repositories` | Allow the Robot account the ability to create new repositories. Once enabled, a new _Team_ called `vault-creator` will be created with `creator` privileges | `false` | No |
| `default_permission` | Default permissions applied for the robot account against newly created repositories | | No |
| `repositories` | Permissions applied to repositories for the Robot account. An example of how content should be formatted can be found [here](examples/repositories.json).  | | No |
| `teams` | Permissions applied to Teams for the Robot account. An example of how content should be formatted can be found [here](examples/teams.json).  | | No |

Let's show examples of how each can be used.

### Static Roles

To manage repositories within the _myorg_ organization and assuming the OAuth token configured previously has the permissions to manage these resources, create a static role which will have permission to create repositories:

```shell
$ vault write quay/static-roles/my-static-account \
  namespace_name=myorg \
  create_repositories=true
```

Credentials for the robot account can be obtained by executing the following command:

```shell
$ vault read quay/static-creds/my-static-account

Key             Value
---             -----
namespace_name    myorg
namespace_type    organization
password        <PASSWORD>
username        <USERNAME>
```

A new robot account will be created in the _myorg_ organization with _creator_ permissions. These credentials will not expire.

To remove the robot account and revoke credentials, execute the following command:

```shell
vault delete quay/static-roles/my-static-account
```

### Dynamic Secrets

Short lived credentials can be created to limit validity of a robot account. Similar to static roles, a role that leverages the dynamic secrets engine can be created using the following command:

```shell
$ vault write quay/roles/my-dynamic-account \
  namespace_name=myorg \
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
namespace_name     myorg
namespace_type     organization
password           <PASSWORD>
username           <USERNAME_WITH_UNIQUE_SUFFIX>
```

A robot account with a dynamically generated name will be created within the _myorg_ organization with permissions to create repositories and contain a unique username suffix.

The _lease_duration_property illustrates how long the credential can be used for. Once this value expires, the robot account will be deleted from Quay. The lease can be extended using the `vault lease renew` command. The `vault lease revoke` command can be used to revoke the active lease and delete the robot account.

The role itself can be removed using the following command:

```shell
vault delete quay/roles/my-dynamic-account
```

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
