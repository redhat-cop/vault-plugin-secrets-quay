package quay

import (
	qc "github.com/redhat-cop/vault-plugin-secrets-quay/client"
)

func (b *quayBackend) createRobot(client *client, robotName string, role *quayRoleEntry) (*qc.RobotAccount, error) {
	// Check if Account Exists
	robotAccount, existingRobotAccountResponse, apiError := client.GetRobotAccount(role.AccountType, role.AccountName, robotName)

	if apiError.Error != nil {
		return nil, apiError.Error
		// A 400 response will be returned with a robot not found. If not, create it
	} else if existingRobotAccountResponse.StatusCode == 400 {

		// Create new Account
		robotAccount, _, apiError = client.CreateRobotAccount(role.AccountType, role.AccountName, robotName)
		if apiError.Error != nil {
			return nil, apiError.Error
		}

		if role.AccountType == organization {
			// Create Teams
			err := b.CreateAssignTeam(client, robotAccount.Name, role)

			if err != nil {
				return nil, err
			}
		}
	}

	return &robotAccount, nil
}

func (b *quayBackend) DeleteRobot(client *client, robotName string, role *quayRoleEntry) error {

	_, apiError := client.DeleteRobotAccount(role.AccountType, role.AccountName, robotName)

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
			teamRole := mapTeamRole(team)

			if len(teamRole) > 0 {
				teams[teamName] = &qc.Team{
					Name: teamName,
					Role: teamRole,
				}
			}
		}
	}

	// Create a Team called vault_creator for access to
	if role.CreateRepositories {
		teams[string(qc.QuayTeamRoleCreator)] = &qc.Team{
			Name: string(qc.QuayTeamRoleCreator),
			Role: qc.QuayTeamRoleCreator,
		}
	}

	return teams
}

func mapTeamRole(teamRole TeamRole) qc.QuayTeamRole {
	switch teamRole {
	case TeamRoleAdmin:
		return qc.QuayTeamRoleAdmin
	case TeamRoleCreator:
		return qc.QuayTeamRoleCreator
	case TeamRoleMember:
		return qc.QuayTeamRoleMember
	}
	return ""
}
