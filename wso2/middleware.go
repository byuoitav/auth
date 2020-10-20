package wso2

import (
	"context"
	"net/http"
	"net/url"
	"sync"

	"github.com/byuoitav/auth/middleware"
	"github.com/byuoitav/auth/session"
	"github.com/segmentio/ksuid"
)

// AuthCodeMiddleware returns a middleware function that authenticates the end user via the
// OAuth2 Authorization Code grant type with WSO2
func (c *Client) AuthCodeMiddleware(sessionStore session.Store, sessionName string) func(http.Handler) http.Handler {

	type state struct {
		URL *url.URL
	}

	// Create state cache
	stateCache := make(map[string]state)
	var stateMux sync.RWMutex

	// function to redirect to login
	redirectToLogin := func(w http.ResponseWriter, r *http.Request) {
		// Save state
		s := state{
			URL: r.URL,
		}

		guid := ksuid.New().String()

		// Store state
		stateMux.Lock()
		stateCache[guid] = s
		stateMux.Unlock()

		// Redirect
		http.Redirect(w, r, c.GetAuthCodeURL(guid), http.StatusSeeOther)
	}

	return func(next http.Handler) http.Handler {

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// If the request has already been authenticated then skip
			if middleware.Authenticated(r) {
				next.ServeHTTP(w, r)
				return
			}

			// Load session
			// Ignoring error as we don't care to log if something went wrong
			s, _ := sessionStore.Get(r, sessionName)

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

				// Update and save session
				s.Values["user"] = claims["net_id"].(string)
				_ = s.Save(r, w)

				// Try to redirect to original destination
				state := r.FormValue("state")
				if state == "" {
					// If we can't find state just remove the query parameters
					http.Redirect(w, r, c.CallbackURL(), http.StatusFound)
					return
				}

				// Pull state from cache and delete if exists
				stateMux.RLock()
				s, ok := stateCache[state]
				if ok {
					delete(stateCache, state)
				}
				stateMux.RUnlock()

				// If state doesn't exist in cache just remove query parameters
				if !ok {
					http.Redirect(w, r, c.CallbackURL(), http.StatusFound)
					return
				}

				// Redirect to original destination
				http.Redirect(w, r, s.URL.String(), http.StatusFound)
				return
			}

			// If there is an existing valid session
			if !s.IsNew {

				// Update inactivity check
				_ = s.Save(r, w)

				//add the claims info to the context and pass the request on
				ctx := context.WithValue(r.Context(), "user", s.Values["user"])
				ctx = context.WithValue(ctx, "passed-auth-check", "true")
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// No valid session
			redirectToLogin(w, r)

		})
	}
}

func (c *Client) JWTValidationMiddleware() func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			jwt := r.Header.Get("X-JWT-Assertion")
			if jwt == "" {
				// Can't validate anything skip
				next.ServeHTTP(w, r)
				return
			}

			claims, err := c.ValidateJWT(jwt)
			if err != nil {
				// JWT invalid or failed to validate
				ctx := context.WithValue(r.Context(), "passed-auth-check", "false")
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			ctx := r.Context()

			// Check for resource owner
			if ro, ok := claims["http://byu.edu/claims/resourceowner_net_id"]; ok {
				ctx = context.WithValue(ctx, "user", ro)
			} else {
				ctx = context.WithValue(ctx, "user", claims["http://byu.edu/claims/client_net_id"])
			}

			// Passed auth check, continue on down the chain
			ctx = context.WithValue(ctx, "passed-auth-check", "true")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
