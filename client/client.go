package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
)

func (c *QuayClient) GetRobotAccount(namespaceType string, namespaceName string, robotName string) (RobotAccount, *http.Response, QuayApiError) {

	req, err := c.newRequest("GET", fmt.Sprintf("/api/v1/%s/%s/robots/%s", namespaceType, namespaceName, robotName), nil)
	if err != nil {
		return RobotAccount{}, nil, QuayApiError{Error: err}
	}
	var getRobotResponse RobotAccount
	resp, err := c.do(req, &getRobotResponse)

	return getRobotResponse, resp, QuayApiError{Error: err}
}

func (c *QuayClient) CreateRobotAccount(namespaceType string, namespaceName string, robotName string) (RobotAccount, *http.Response, QuayApiError) {

	req, err := c.newRequest("PUT", fmt.Sprintf("/api/v1/%s/%s/robots/%s", namespaceType, namespaceName, robotName), nil)
	if err != nil {
		return RobotAccount{}, nil, QuayApiError{Error: err}
	}
	var createRobotResponse RobotAccount
	resp, err := c.do(req, &createRobotResponse)

	return createRobotResponse, resp, QuayApiError{Error: err}
}

func (c *QuayClient) DeleteRobotAccount(namespaceType string, namespaceName string, robotName string) (*http.Response, QuayApiError) {

	req, err := c.newRequest("DELETE", fmt.Sprintf("/api/v1/%s/%s/robots/%s", namespaceType, namespaceName, robotName), nil)
	if err != nil {
		return nil, QuayApiError{Error: err}
	}
	resp, err := c.do(req, nil)

	return resp, QuayApiError{Error: err}
}

func (c *QuayClient) RegenerateRobotAccountPassword(namespaceType string, namespaceName string, robotName string) (RobotAccount, *http.Response, QuayApiError) {

	req, err := c.newRequest("POST", fmt.Sprintf("/api/v1/%s/%s/robots/%s/regenerate", namespaceType, namespaceName, robotName), nil)
	if err != nil {
		return RobotAccount{}, nil, QuayApiError{Error: err}
	}
	var regenerateRobotAccountResponse RobotAccount
	resp, err := c.do(req, &regenerateRobotAccountResponse)

	return regenerateRobotAccountResponse, resp, QuayApiError{Error: err}
}

func (c *QuayClient) CreateTeam(namespaceName string, team *Team) (Team, *http.Response, QuayApiError) {

	req, err := c.newRequest("PUT", fmt.Sprintf("/api/v1/organization/%s/team/%s", namespaceName, team.Name), team)
	if err != nil {
		return Team{}, nil, QuayApiError{Error: err}
	}
	var createTeamResponse Team
	resp, err := c.do(req, &createTeamResponse)

	return createTeamResponse, resp, QuayApiError{Error: err}
}

func (c *QuayClient) AddTeamMember(namespaceName, teamName, memberName string) (*http.Response, QuayApiError) {

	req, err := c.newRequest("PUT", fmt.Sprintf("/api/v1/organization/%s/team/%s/members/%s", namespaceName, teamName, memberName), nil)
	if err != nil {
		return nil, QuayApiError{Error: err}
	}
	resp, err := c.do(req, nil)

	return resp, QuayApiError{Error: err}
}

func (c *QuayClient) GetPrototypesByOrganization(organizationName string) (PrototypesResponse, *http.Response, QuayApiError) {

	req, err := c.newRequest("GET", fmt.Sprintf("/api/v1/organization/%s/prototypes", organizationName), nil)
	if err != nil {
		return PrototypesResponse{}, nil, QuayApiError{Error: err}
	}
	var getPrototypeResponse PrototypesResponse
	resp, err := c.do(req, &getPrototypeResponse)

	return getPrototypeResponse, resp, QuayApiError{Error: err}
}

func (c *QuayClient) CreateRobotPermissionForOrganization(organizationName string, robotAccount string, role string) (Prototype, *http.Response, QuayApiError) {

	robotOrganizationPermission := Prototype{
		Role: role,
		Delegate: PrototypeDelegate{
			Kind:      "user",
			Name:      robotAccount,
			Robot:     true,
			OrgMember: true,
		},
	}

	req, err := c.newRequest("POST", fmt.Sprintf("/api/v1/organization/%s/prototypes", organizationName), robotOrganizationPermission)
	if err != nil {
		return Prototype{}, nil, QuayApiError{Error: err}
	}
	var newPrototypeResponse Prototype
	resp, err := c.do(req, &newPrototypeResponse)

	return newPrototypeResponse, resp, QuayApiError{Error: err}
}

func (c *QuayClient) GetRobotPermissions(organizationName, robotName string) (PermissionsResponse, *http.Response, QuayApiError) {

	req, err := c.newRequest("GET", fmt.Sprintf("/api/v1/organization/%s/robots/%s/permissions", organizationName, robotName), nil)
	if err != nil {
		return PermissionsResponse{}, nil, QuayApiError{Error: err}
	}
	var getPermissionsResponse PermissionsResponse
	resp, err := c.do(req, &getPermissionsResponse)

	return getPermissionsResponse, resp, QuayApiError{Error: err}
}

func (c *QuayClient) UpdateRepositoryUserPermission(namespace, repositoryName, roleName, permission string) (*Team, *http.Response, QuayApiError) {

	robotName := fmt.Sprintf("%s+%s", namespace, roleName)

	req, err := c.newRequest("PUT", fmt.Sprintf("/api/v1/repository/%s/%s/permissions/user/%s", namespace, repositoryName, robotName), &PermissionUpdateRequest{
		Role: permission,
	})
	if err != nil {
		return nil, nil, QuayApiError{Error: err}
	}
	var createTeamResponse Team
	resp, err := c.do(req, &createTeamResponse)

	return &createTeamResponse, resp, QuayApiError{Error: err}
}

func (c *QuayClient) GetRepositoriesForNamespace(namespace string) ([]Repository, *http.Response, QuayApiError) {

	repositories := []Repository{}
	var resp *http.Response
	nextPageParameter := ""

	for {

		req, err := c.newRequest("GET", fmt.Sprintf("/api/v1/repository?namespace=%s%s", namespace, nextPageParameter), nil)
		if err != nil {
			return repositories, nil, QuayApiError{Error: err}
		}

		var getRepositoriesResponse RepositoriesResponse
		resp, err = c.do(req, &getRepositoriesResponse)

		if resp.StatusCode == 200 {

			repositories = append(repositories, getRepositoriesResponse.Repositories...)

			if getRepositoriesResponse.NextPage != nil {
				nextPageParameter = fmt.Sprintf("&next_page=%s", *getRepositoriesResponse.NextPage)
				continue
			}

		}

		return repositories, resp, QuayApiError{Error: err}

	}

}

func (c *QuayClient) newRequest(method, path string, body interface{}) (*http.Request, error) {
	rel, err := url.Parse(path)
	if err != nil {
		return nil, err
	}
	u := c.baseURL.ResolveReference(rel)
	var buf io.ReadWriter
	if body != nil {
		buf = new(bytes.Buffer)
		err := json.NewEncoder(buf).Encode(body)
		if err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequest(method, u.String(), buf)

	if !isZeroOfUnderlyingType(c.authToken) {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	return req, nil
}
func (c *QuayClient) do(req *http.Request, v interface{}) (*http.Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if v != nil {

		if _, ok := v.(*StringValue); ok {
			responseData, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return resp, err
			}
			responseObject := v.(*StringValue)
			responseObject.Value = string(responseData)

		} else {
			err = json.NewDecoder(resp.Body).Decode(v)
			if err != nil {
				return resp, err
			}
		}

	}

	return resp, err
}

func NewClient(httpClient *http.Client, baseUrl string, authToken string) (*QuayClient, error) {
	quayClient := QuayClient{
		httpClient: httpClient,
		authToken:  authToken,
	}

	parsedUrl, err := url.Parse(baseUrl)

	if err != nil {
		return nil, err
	}

	quayClient.baseURL = parsedUrl

	return &quayClient, nil
}

func isZeroOfUnderlyingType(x interface{}) bool {
	return reflect.DeepEqual(x, reflect.Zero(reflect.TypeOf(x)).Interface())
}
