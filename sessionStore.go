package auth

// Session represents a user session and contains pertenant functions for operating
// on that session
type Session interface {
	ID() string
	Get(key string) (value string, err error)
	Set(key, value string) error
	Drop(key string) error
}

// SessionStore defines the requirements for an implementation of a session store
type SessionStore interface {
	NewSession() Session
	GetSession(id string) (Session, error)
	DropSession(id string) error
}
