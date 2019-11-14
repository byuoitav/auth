package wso2

import (
	"fmt"
	"net/http"
)

// Do performs the given request utilizing the WSO2 client
func (c *Client) Do(req *http.Request) (*http.Response, error) {

	token, err := c.GetToken()
	if err != nil {
		return nil, fmt.Errorf("Error while trying to get a token: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Error while making request: %w", err)
	}

	return res, nil
}

// Get performs a GET request to the given url utilizing the WSO2 client
func (c *Client) Get(url string) (*http.Response, error) {

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("Error while building request: %w", err)
	}

	return c.Do(req)
}
