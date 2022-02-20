package quay

import (
	"fmt"

	qc "github.com/redhat-cop/vault-plugin-secrets-quay/client"
)

var (
	vaultCreator = fmt.Sprintf("%s-%s", Vault, TeamRoleCreator)
)

const (
	Vault string = "vault"
)

func (b *quayBackend) createRobot(client *client, robotName string, role *quayRoleEntry) (*qc.RobotAccount, error) {
	// Check if Account Exists
	robotAccount, existingRobotAccountResponse, apiError := client.GetRobotAccount(role.AccountType.String(), role.AccountName, robotName)

	if apiError.Error != nil {
		return nil, apiError.Error
		// A 400 response will be returned with a robot not found. If not, create it
	} else if existingRobotAccountResponse.StatusCode == 400 {

		// Create new Account
		robotAccount, _, apiError = client.CreateRobotAccount(role.AccountType.String(), role.AccountName, robotName)
		if apiError.Error != nil {
			return nil, apiError.Error
		}
	}

	if role.AccountType == organization {
		// Create Teams
		err := b.CreateAssignTeam(client, robotAccount.Name, role)

		if err != nil {
			return nil, err
		}

		// Create Default Permission
		if role.DefaultPermission != nil {
			organizationPrototypes, organizationPrototypesResponse, organizationPrototypesError := client.GetPrototypesByOrganization(role.AccountName)

			if organizationPrototypesError.Error != nil || organizationPrototypesResponse.StatusCode != 200 {
				return nil, organizationPrototypesError.Error
			}

			if found := isRobotAccountInPrototypeByRole(organizationPrototypes.Prototypes, robotAccount.Name, role.DefaultPermission.String()); !found {

				_, robotPrototypeResponse, robotPrototypeError := client.CreateRobotPermissionForOrganization(role.AccountName, robotAccount.Name, role.DefaultPermission.String())

				if robotPrototypeError.Error != nil || robotPrototypeResponse.StatusCode != 200 {
					return nil, robotPrototypeError.Error
				}

			}
		}

	}

	// Manage Repositories
	if role.Repositories != nil {
		// Get Robot Permissions
		robotPermissions, robotPermissionsResponse, robotPermissionsError := client.GetRobotPermissions(role.AccountName, robotName)

		if robotPermissionsError.Error != nil || robotPermissionsResponse.StatusCode != 200 {
			return nil, robotPermissionsError.Error
		}

		// Get Repositories
		namespaceRepositories, namespaceRepositoriesResponse, namespaceRepositoriesError := client.GetRepositoriesForNamespace(role.AccountName)

		if namespaceRepositoriesError.Error != nil || namespaceRepositoriesResponse.StatusCode != 200 {
			return nil, robotPermissionsError.Error
		}

		for repositoryName, permission := range *role.Repositories {

			// Verify repository exists in the organization
			if updateRepository := repositoryExists(repositoryName, &namespaceRepositories.Repositories); updateRepository {
				// Check to see if permission already exists on robot account
				if updatePermissions := shouldNeedUpdateRepositoryPermissions(repositoryName, permission.String(), &robotPermissions.Permissions); updatePermissions {
					_, repositoryPermissionUpdateResponse, repositoryPermissionError := client.UpdateRepositoryUserPermission(role.AccountName, repositoryName, robotName, permission.String())

					if repositoryPermissionError.Error != nil || repositoryPermissionUpdateResponse.StatusCode != 200 {
						return nil, repositoryPermissionError.Error
					}
				}
			}
		}
	}

	return &robotAccount, nil
}

func (b *quayBackend) DeleteRobot(client *client, robotName string, role *quayRoleEntry) error {

	_, apiError := client.DeleteRobotAccount(role.AccountType.String(), role.AccountName, robotName)

	return apiError.Error
}

func (b *quayBackend) CreateAssignTeam(client *client, robotName string, role *quayRoleEntry) error {

	teams := b.assembleTeams(role)

	for _, team := range teams {
		// Create Team
		_, _, err := client.CreateTeam(role.AccountName, team)

		if err.Error != nil {
			return err.Error
		}

		// Add member to team
		_, err = client.AddTeamMember(role.AccountName, team.Name, robotName)

		if err.Error != nil {
			return err.Error
		}

	}

	return nil
}

func (*quayBackend) assembleTeams(role *quayRoleEntry) map[string]*qc.Team {
	teams := map[string]*qc.Team{}

	// Build Teams
	if role.Teams != nil {
		for teamName, team := range *role.Teams {

			teams[teamName] = &qc.Team{
				Name: teamName,
				Role: qc.QuayTeamRole(team.String()),
			}

		}
	}

	// Create a Team called vault_creator for access to
	if role.CreateRepositories {
		teams[vaultCreator] = &qc.Team{
			Name: vaultCreator,
			Role: qc.QuayTeamRoleCreator,
		}
	}

	return teams
}

func isRobotAccountInPrototypeByRole(prototypes []qc.Prototype, robotAccount string, role string) bool {

	for _, prototype := range prototypes {

		if prototype.Role == role && prototype.Delegate.Robot == true && prototype.Delegate.Name == robotAccount {
			return true
		}

	}

	return false

}

func shouldNeedUpdateRepositoryPermissions(repositoryName string, repositoryPermission string, quayPermissions *[]qc.Permission) bool {

	for _, quayPermission := range *quayPermissions {
		if repositoryName == quayPermission.Repository.Name && repositoryPermission == quayPermission.Role.String() {
			return false
		}
	}

	return true
}

func repositoryExists(repositoryName string, repositories *[]qc.Repository) bool {

	for _, repository := range *repositories {
		if repositoryName == repository.Name {
			return true
		}
	}

	return false
}
