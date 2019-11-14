package wso2

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GetToken returns a current token for the client
func (c *Client) GetToken() (string, error) {

	c.tokenMux.RLock()
	defer c.tokenMux.RUnlock()

	// If the current token is expired or does not exist then refresh
	if c.tokenExp.IsZero() || time.Now().After(c.tokenExp) {
		c.tokenMux.RUnlock()
		c.refreshToken()
		c.tokenMux.RLock()
	}

	return c.token, nil
}

// ForceTokenRefresh forces the client to attempt to refresh the current
// token immediately
func (c *Client) ForceTokenRefresh() error {

	err := c.refreshToken()
	if err != nil {
		return fmt.Errorf("Error while refreshing token: %w", err)
	}

	return nil
}

func (c *Client) refreshToken() error {

	c.tokenMux.Lock()
	defer c.tokenMux.Unlock()

	refreshURI := fmt.Sprintf("%s/token", c.GatewayURL)

	data := url.Values{}
	data.Set("grant_type", "client_credentials")

	req, err := http.NewRequest("POST", refreshURI, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("Error while trying to build request: %w", err)
	}

	req.SetBasicAuth(c.ClientID, c.ClientSecret)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("Error while making refresh call: %w", err)
	}

	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(res.Body)
		return fmt.Errorf("Refresh call returned non 200 status code: %d: %s", res.StatusCode, body)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("Error while trying to read response body from refresh call: %w", err)
	}

	tokenRes := struct {
		expiresIn int    `json:"expires_in"`
		token     string `json:"access_token"`
	}{}

	err = json.Unmarshal(body, &tokenRes)
	if err != nil {
		return fmt.Errorf("Error while parsing refresh token call response body: %w", err)
	}

	c.token = tokenRes.token
	c.tokenExp = time.Now().Add(time.Second * time.Duration(tokenRes.expiresIn))

	return nil

}