package wso2

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/byuoitav/auth/middleware"
	"github.com/dgrijalva/jwt-go"
	"github.com/segmentio/ksuid"
)

var setup sync.Once
var signingKey = make([]byte, 0)

// AuthCodeMiddleware returns a handler that authenticates the end user via the
// OAuth2 Authorization Code grant type with WSO2
func (c *Client) AuthCodeMiddleware(next http.Handler) http.Handler {
	setup.Do(func() {
		signingKey := make([]byte, 64)
		_, err := rand.Read(signingKey)
		if err != nil {
			panic(fmt.Sprintf("Couldn't autogenerate signing key: %s", err))
		}
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// If the request has already been authenticated then skip
		if middleware.Authenticated(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Check for authorization code from just having logged in
		authCode := r.FormValue("code")
		if authCode != "" {

			res, err := c.ValidateAuthorizationCode(authCode)
			if err != nil {
				// Just continue down the chain without authenticating and let
				// each application handle failed auth how they will
				next.ServeHTTP(w, r)
				return
			}

			// Check the ID token for validity
			claims, err := c.ValidateJWT(res.IDToken)
			if err != nil {
				// Just continue down the chain without authenticating and let
				// each application handle failed auth how they will
				next.ServeHTTP(w, r)
				return
			}

			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"exp": time.Now().Add(time.Hour * 8).Format(time.RFC3339),
				"usr": claims["net_id"].(string),
			})

			signedToken, err := token.SignedString([]byte(signingKey))
			if err != nil {
				// Just continue down the chain without authenticating and let
				// each application handle failed auth how they will
				next.ServeHTTP(w, r)
				return
			}

			// Derive the cookie domain from the hostname of the requested URL
			domain := r.URL.Hostname()

			sessionCookie := http.Cookie{
				Name:     "JWT-TOKEN",
				Value:    signedToken,
				HttpOnly: false,
				Secure:   false,
				Domain:   domain,
			}

			http.SetCookie(w, &sessionCookie)

			// Try to redirect to original destination
			state := r.FormValue("state")
			if state == "" {
				// If we can't find state just remove the query parameters
				http.Redirect(w, r, c.callbackURL, http.StatusFound)
				return
			}

			// Pull state from cache and delete if exists
			c.stateMux.RLock()
			s, ok := c.stateCache[state]
			if ok {
				delete(c.stateCache, state)
			}
			c.stateMux.RUnlock()

			// If state doesn't exist in cache just remove query parameters
			if !ok {
				http.Redirect(w, r, c.callbackURL, http.StatusFound)
				return
			}

			// Redirect to original destination
			http.Redirect(w, r, s.URL.String(), http.StatusFound)
		}

		// Check for existing session
		j, err := r.Cookie("JWT-TOKEN")
		if err != nil {
			// No existing session, redirect to login
			c.redirectToLogin(w, r)
			return
		}

		token, err := jwt.Parse(j.Value, func(T *jwt.Token) (interface{}, error) {
			if T.Method.Alg() != "HS256" {
				return "", fmt.Errorf("Invalid signing method %v", T.Method.Alg())
			}
			return []byte(signingKey), nil
		})
		if err != nil {
			c.redirectToLogin(w, r)
			return
		}

		exp, ok := token.Claims.(jwt.MapClaims)["exp"]
		if ok {
			//jwt has an expiration time
			t, err := time.Parse(time.RFC3339, exp.(string))
			if err != nil {
				// Token has no parsable expiration date restart
				c.redirectToLogin(w, r)
				return
			}

			//the jwt is still valid
			if !t.Before(time.Now()) {
				//add the claims info to the context and pass the request on

				ctx := context.WithValue(r.Context(), "client", token)
				ctx = context.WithValue(ctx, "user", token.Claims.(jwt.MapClaims)["usr"].(string))
				ctx = context.WithValue(ctx, "passed-auth-check", "true")
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// JWT is expired
			c.redirectToLogin(w, r)
			return

		}
		// No exp claim
		c.redirectToLogin(w, r)

	})
}

func (c *Client) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	// Save state
	s := state{
		URL: r.URL,
	}

	guid := ksuid.New().String()

	// Store state
	c.stateMux.Lock()
	c.stateCache[guid] = s
	c.stateMux.Unlock()

	// Redirect
	http.Redirect(w, r, c.GetAuthCodeURL(guid), http.StatusSeeOther)
}
