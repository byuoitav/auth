package cookiestore

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"time"

	"github.com/byuoitav/auth/session"
	"github.com/dgrijalva/jwt-go"
)

type Store struct {
	ttl    int
	maxAge int
	key    []byte
}

func NewStore(opts ...Option) *Store {
	signingKey := make([]byte, 64)
	_, err := rand.Read(signingKey)
	if err != nil {
		panic(fmt.Sprintf("Couldn't autogenerate signing key: %s", err))
	}

	s := &Store{
		ttl:    120,   // Two hours
		maxAge: 10080, // One week
		key:    signingKey,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

func (s *Store) new(name string) *session.Session {
	se := session.NewSession(s, name)

	// Set exp claim to the MaxAge of the session
	se.Values["exp"] = time.Now().Add(time.Minute * time.Duration(s.maxAge)).Format(time.RFC3339)

	return se
}

func (s *Store) Get(r *http.Request, name string) (*session.Session, error) {
	// Check for existing session
	j, err := r.Cookie(name)
	if err != nil {
		// No existing session, create a new one
		return s.new(name), nil
	}

	// Validate the existing session
	token, err := jwt.Parse(j.Value, func(T *jwt.Token) (interface{}, error) {
		if T.Method.Alg() != "HS256" {
			// Invalid signing method, return new session
			return s.new(name), fmt.Errorf("Invalid signing method %v", T.Method.Alg())
		}
		return []byte(s.key), nil
	})
	if err != nil {
		// Signature invalid, return new session
		return s.new(name), fmt.Errorf("Session cookie invalid: %s", err)
	}

	// Check that the session hasn't passed max age
	exp, ok := token.Claims.(jwt.MapClaims)["exp"]
	if !ok {
		// No expiration claim, new session
		return s.new(name), fmt.Errorf("Session cookie lacks exp claim")
	}

	//jwt has an expiration time
	t, err := time.Parse(time.RFC3339, exp.(string))
	if err != nil {
		// Token has no parsable expiration date restart
		return s.new(name), fmt.Errorf("Session cookie exp claim unparsable")
	}

	// if the jwt is expired
	if t.Before(time.Now()) {
		return s.new(name), fmt.Errorf("Session cookie expired")
	}

	// If we care to check for inactivity
	if s.ttl > 0 {
		// Check that the session hasn't hit the inactivity limit
		iat, ok := token.Claims.(jwt.MapClaims)["iat"]
		if !ok {
			// No expiration claim, new session
			return s.new(name), fmt.Errorf("Session cookie lacks iat claim")
		}

		//jwt has an issued at time
		it, err := time.Parse(time.RFC3339, iat.(string))
		if err != nil {
			// Token has no parsable expiration date restart
			return s.new(name), fmt.Errorf("Session cookie iat claim unparsable")
		}

		// if the jwt has passed inactivity window
		if time.Since(it) > time.Duration(s.ttl)*time.Minute {
			return s.new(name), fmt.Errorf("Session inactivity limit passed")
		}
	}

	// Load valid session
	se := s.new(name)
	se.IsNew = false
	se.Values = token.Claims.(jwt.MapClaims)

	return se, nil

}

func (s *Store) Save(r *http.Request, w http.ResponseWriter, se *session.Session) error {
	// Populate the claims
	claims := jwt.MapClaims{}
	for k, v := range se.Values {
		claims[k] = v
	}

	// Update iat (issued at) claim to now
	claims["iat"] = time.Now().Format(time.RFC3339)

	// Create and sign token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString([]byte(s.key))
	if err != nil {
		return fmt.Errorf("failed to sign token: %w", err)
	}

	// Derive the cookie domain from the hostname of the requested URL
	domain := r.URL.Hostname()

	// Write cookie
	sessionCookie := &http.Cookie{
		Name:     se.Name(),
		Value:    signedToken,
		HttpOnly: false,
		Secure:   false,
		Domain:   domain,
	}

	http.SetCookie(w, sessionCookie)
	return nil

}

func (s *Store) Drop(r *http.Request, w http.ResponseWriter, name string) error {
	c := &http.Cookie{
		Name:     name,
		Value:    "",
		HttpOnly: false,
		Secure:   false,
		Domain:   r.URL.Hostname(),
	}

	http.SetCookie(w, c)
	return nil
}
