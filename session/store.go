package session

import "net/http"

// Store defines the requirements for an implementation of a session store
type Store interface {
	// Get should do one of two things:
	// 1. It should return an existing session for the request
	// 2. It should return a new session in cases where a session cannot be found
	// The error returned by Get will be populated if there was any unforseen
	// error with the store while attempting to retrieve an existing session
	Get(r *http.Request, name string) (*Session, error)
	// Save saves the given session for the given request
	Save(r *http.Request, w http.ResponseWriter, s *Session) error
	// Drop drops the given session name for the given request
	Drop(r *http.Request, w http.ResponseWriter, name string) error
}
