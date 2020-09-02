package wso2

import (
	"context"
	"net/http"
	"net/url"
	"sync"

	"github.com/byuoitav/auth/middleware"
	"github.com/byuoitav/auth/session"
	"github.com/byuoitav/auth/wso2"
	"github.com/segmentio/ksuid"
)

type state struct {
	URL *url.URL
}

type Client struct {
	wso2Client   *wso2.Client
	sessionStore session.Store
	sessionName  string

	stateCache map[string]state
	stateMux   sync.RWMutex
}

func NewClient(wso2Client *wso2.Client, sessionStore session.Store, sessionName string) *Client {
	return &Client{
		wso2Client:   wso2Client,
		sessionStore: sessionStore,
		sessionName:  sessionName,

		stateCache: make(map[string]state),
	}
}

// AuthCodeMiddleware returns a handler that authenticates the end user via the
// OAuth2 Authorization Code grant type with WSO2
func (c *Client) AuthCodeMiddleware(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// If the request has already been authenticated then skip
		if middleware.Authenticated(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Load session
		// Ignoring error as we don't care to log if something went wrong
		s, _ := c.sessionStore.Get(r, c.sessionName)

		// Check for authorization code from just having logged in
		authCode := r.FormValue("code")
		if authCode != "" {

			res, err := c.wso2Client.ValidateAuthorizationCode(authCode)
			if err != nil {
				// Just continue down the chain without authenticating and let
				// each application handle failed auth how they will
				next.ServeHTTP(w, r)
				return
			}

			// Check the ID token for validity
			claims, err := c.wso2Client.ValidateJWT(res.IDToken)
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
				http.Redirect(w, r, c.wso2Client.CallbackURL(), http.StatusFound)
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
				http.Redirect(w, r, c.wso2Client.CallbackURL(), http.StatusFound)
				return
			}

			// Redirect to original destination
			http.Redirect(w, r, s.URL.String(), http.StatusFound)
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
	http.Redirect(w, r, c.wso2Client.GetAuthCodeURL(guid), http.StatusSeeOther)
}
