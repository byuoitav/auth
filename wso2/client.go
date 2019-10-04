package wso2

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var errCantIdentifyKey = fmt.Errorf("Unable to identify key used for signing")

// Client represents an instance of a WSO2 client and contains all the
// configuration values necessary to run
type Client struct {
	GatewayURL   string
	ClientID     string
	ClientSecret string
	CallbackURL  string
	keyCache     map[string]*rsa.PublicKey
	keyCacheExp  time.Time
	cacheMux     sync.RWMutex
}

// AuthCodeResponse represents the response given by WSO2 when exchanging an
// authorization code for a token
type AuthCodeResponse struct {
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
}

// ValidateAuthorizationCode validates the given authorization code and returns
// the response including the token, refresh token, and ID token if it exists.
func (c *Client) ValidateAuthorizationCode(ac string) (AuthCodeResponse, error) {

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", ac)
	data.Set("redirect_uri", c.CallbackURL)

	// Send back the auth code in exchange for a token and refresh token
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/token", c.GatewayURL), strings.NewReader(data.Encode()))
	if err != nil {
		return AuthCodeResponse{}, fmt.Errorf("Error while trying to create authorization code request: %w", err)
	}

	req.SetBasicAuth(c.ClientID, c.ClientSecret)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		return AuthCodeResponse{}, fmt.Errorf("Error while making Authorization Code request: %w", err)
	}

	// Read the body and parse it
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return AuthCodeResponse{}, fmt.Errorf("Error while trying to read the Auth Code Response body: %w", err)
	}

	codeRes := AuthCodeResponse{}
	err = json.Unmarshal(b, &codeRes)
	if err != nil {
		return AuthCodeResponse{}, fmt.Errorf("Error while trying to unmarshal the auth code response: %w", err)
	}

	return codeRes, nil

}

// GetAuthCodeURL returns the authorize URL to redirect users to for the
// Authorization Code OAuth2.0 Grant type
func (c *Client) GetAuthCodeURL() string {

	return fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid&state=newstate",
		c.GatewayURL, c.ClientID, c.CallbackURL)

}

// ValidateJWT validates the given JWT and if it is valid returns the claims
func (c *Client) ValidateJWT(j string) (map[string]interface{}, error) {

	// Refresh the cache if it is not set or expired
	if c.keyCacheExp.IsZero() || time.Now().After(c.keyCacheExp) {
		c.refreshKeyCache()
	}

	// Try to validate using automatic key selection
	token, err := jwt.Parse(j, c.validationFunc(nil))
	if err != nil {

		// If we weren't able to figure out which key to use
		if strings.Contains(err.Error(), errCantIdentifyKey.Error()) {

			c.cacheMux.RLock()
			defer c.cacheMux.RUnlock()
			for _, k := range c.keyCache {

				token, err := jwt.Parse(j, c.validationFunc(k))
				if ve, ok := err.(*jwt.ValidationError); ok {

					// if the error is due to invalid signature then continue
					if ve.Errors&jwt.ValidationErrorSignatureInvalid != 0 {
						continue
					}
				}
				// for any other error break because something else is wrong
				if err != nil {
					break
				}

				// If we found the right signature then we're good
				if token.Valid {
					return token.Claims.(jwt.MapClaims), nil
				}
			}

			// The last error will fall through the normal processing
		}
		if ve, ok := err.(*jwt.ValidationError); ok {

			if ve.Errors&jwt.ValidationErrorExpired != 0 {
				return nil, fmt.Errorf("JWT is expired")
			}
			if ve.Errors&jwt.ValidationErrorSignatureInvalid != 0 {
				return nil, fmt.Errorf("JWT signature is invalid")
			}

		}

		// for all other errors just return a generic error
		return nil, fmt.Errorf("Failed to validate token: %w", err)
	}

	return token.Claims.(jwt.MapClaims), nil

}

func (c *Client) validationFunc(k *rsa.PublicKey) jwt.Keyfunc {

	return func(token *jwt.Token) (interface{}, error) {
		// Check that the signing method is RSA (this check is required due to a security
		// vulnerability in the JWT standard)
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// Parse the claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, fmt.Errorf("Unable to parse claims")
		}

		// Check that the issuer is who we expect
		if iss, ok := claims["iss"].(string); ok {
			if iss != c.GatewayURL && !strings.HasPrefix(iss, "https://wso2-is.byu.edu") {
				return nil, fmt.Errorf("Unexpected issuer: %s", iss)
			}
		}

		// If a key has been passed in use that
		if k != nil {
			return k, nil
		}

		// Otherwise, try to determine the key
		if x5t, ok := token.Header["x5t"].(string); ok {
			if key, ok := c.keyCache[x5t]; ok {
				return key, nil
			}

			return nil, fmt.Errorf("Unrecognized key used for JWT signature: %s", x5t)
		}

		return nil, errCantIdentifyKey

	}
}

func (c *Client) refreshKeyCache() error {

	// Get openid-configuration document
	res, err := http.Get(fmt.Sprintf("%s/.well-known/openid-configuration", c.GatewayURL))
	if err != nil {
		return fmt.Errorf("Error while trying to get openid configuration: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("Got non 200 response from openid configuration endpoint")
	}

	oidConfig := struct {
		JWKSURI string `json:"jwks_uri"`
	}{}

	err = json.NewDecoder(res.Body).Decode(&oidConfig)
	res.Body.Close()
	if err != nil {
		return fmt.Errorf("Error while trying to unmarshal openid config: %w", err)
	}

	// Get JWKS document
	res, err = http.Get(oidConfig.JWKSURI)
	if err != nil {
		return fmt.Errorf("Error while trying to get JWKS document: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("Got non 200 status code from JWKS endpoint")
	}

	jwks := struct {
		Keys []struct {
			ID  string   `json:"kid"`
			X5C []string `json:"x5c"`
		} `json:"keys"`
	}{}

	err = json.NewDecoder(res.Body).Decode(&jwks)
	res.Body.Close()
	if err != nil {
		return fmt.Errorf("Error while trying to unmarshal JWKS doc: %w", err)
	}

	// Calculate new cache expiry time to add
	cacheExp := res.Header.Get("cache-control")
	cacheExp = strings.TrimPrefix(cacheExp, "public max-age=")
	expSeconds, err := strconv.Atoi(cacheExp)
	if err != nil || expSeconds == 0 {
		expSeconds = 3600
	}

	// Add keys to cache
	c.cacheMux.Lock()

	c.keyCache = make(map[string]*rsa.PublicKey)

	for _, k := range jwks.Keys {
		cert, err := x509.ParsePKCS1PublicKey([]byte(k.X5C[0]))
		if err != nil {
			return fmt.Errorf("Failed to parse key: %w", err)
		}

		c.keyCache[k.ID] = cert
	}

	// Update cache expiry timestamp
	c.keyCacheExp = time.Now().Add(time.Second * time.Duration(expSeconds))

	c.cacheMux.Unlock()

	return nil
}
