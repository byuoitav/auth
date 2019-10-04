package memory

import (
	"errors"

	"github.com/byuoitav/auth"
	"github.com/google/uuid"
)

// ErrSessionNotFound is returned when a given session is not found in the store
var ErrSessionNotFound = errors.New("The given session ID does not exist in the store")

// SessionStore represents an instantiation of the in-memory session store
type SessionStore struct {
	sessions map[string]*Session
}

// NewSessionStore returns a new instantiation of an in-memory session store
func NewSessionStore() auth.SessionStore {
	return &SessionStore{
		sessions: make(map[string]*Session),
	}
}

// NewSession creates a new session and returns it
func (s *SessionStore) NewSession() auth.Session {
	sn := Session{
		id:   uuid.New().String(),
		data: make(map[string]string),
	}
	s.sessions[sn.id] = &sn
	return &sn
}

// GetSession returns the given session if it exists or an error otherwise
func (s *SessionStore) GetSession(id string) (auth.Session, error) {

	if sn, ok := s.sessions[id]; ok {
		return sn, nil
	}

	return nil, ErrSessionNotFound

}

// DropSession drops the given session from the store if it exists
func (s *SessionStore) DropSession(id string) error {

	if _, ok := s.sessions[id]; ok {
		delete(s.sessions, id)
		return nil
	}

	return ErrSessionNotFound

}
