package wso2

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/byuoitav/common/log"
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

	token    string
	tokenExp time.Time
	tokenMux sync.RWMutex
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
	if err != nil {
		return AuthCodeResponse{}, fmt.Errorf("Error while making Authorization Code request: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(res.Body)
		return AuthCodeResponse{}, fmt.Errorf("Got non 200 response back from the token endpoint: %d %s", res.StatusCode, body)
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

	log.L.Debugf("Validating token...")
	// Try to validate using automatic key selection
	token, err := jwt.Parse(j, c.validationFunc(nil))
	if err != nil {

		// If we weren't able to figure out which key to use
		if strings.Contains(err.Error(), errCantIdentifyKey.Error()) {

			log.L.Debugf("key thumbprint not specified trying all keys")

			c.cacheMux.RLock()
			defer c.cacheMux.RUnlock()
			for x5t, k := range c.keyCache {

				log.L.Debugf("trying key: %s", x5t)

				token, newErr := jwt.Parse(j, c.validationFunc(k))
				if ve, ok := newErr.(*jwt.ValidationError); ok {

					// if the error is due to invalid signature then continue
					if ve.Errors&jwt.ValidationErrorSignatureInvalid != 0 {
						log.L.Debugf("bad signature trying next key")
						continue
					}

					// Ignore issued at errors due to WSO2
					if ve.Errors&jwt.ValidationErrorIssuedAt != 0 {
						return token.Claims.(jwt.MapClaims), nil
					}
				}
				// for any other error break because something else is wrong
				if newErr != nil {
					log.L.Debugf("Breaking due to other error")
					err = newErr
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
		log.L.Debugf("Key passed in: %s", k)
		if k != nil {
			log.L.Debugf("Returning passed in key")
			return k, nil
		}

		log.L.Debugf("Trying to auto identify necessary key")

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

	log.L.Debugf("Refreshing key cache")

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
			X5T string `json:"x5t"`
			E   string `json:"e"`
			N   string `json:"n"`
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
	log.L.Debugf("cache expires in %d seconds", expSeconds)

	// Add keys to cache
	c.cacheMux.Lock()
	defer c.cacheMux.Unlock()

	c.keyCache = make(map[string]*rsa.PublicKey)

	for _, k := range jwks.Keys {
		cert, err := eNToPubKey(k.E, k.N)
		if err != nil {
			log.L.Errorf("Failed to parse key: %s", err)
			return fmt.Errorf("Failed to parse key: %w", err)
		}

		log.L.Debugf("inserting key into cache: %s", k.X5T)
		c.keyCache[k.X5T] = cert
	}

	// Update cache expiry timestamp
	c.keyCacheExp = time.Now().Add(time.Second * time.Duration(expSeconds))

	return nil
}

func eNToPubKey(e, n string) (*rsa.PublicKey, error) {

	ebytes, err := base64.StdEncoding.DecodeString(e)
	if err != nil {
		return nil, fmt.Errorf("Error while decoding e: %w", err)
	}

	if len(ebytes) < 8 {
		padding := make([]byte, 8-len(ebytes), 8)
		ebytes = append(padding, ebytes...)
	}

	var eInt uint64
	err = binary.Read(bytes.NewReader(ebytes), binary.BigEndian, &eInt)
	if err != nil {
		return nil, fmt.Errorf("Error while reading e: %w", err)
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		return nil, fmt.Errorf("Error while decoding n: %w", err)
	}

	nInt := big.NewInt(0)
	nInt.SetBytes(nBytes)

	return &rsa.PublicKey{
		N: nInt,
		E: int(eInt),
	}, nil

}
