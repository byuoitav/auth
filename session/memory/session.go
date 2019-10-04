package memory

import "errors"

// ErrKeyDoesNotExist is returned when a session data key is used that does not exist
var ErrKeyDoesNotExist = errors.New("The specified key does not exist for this session")

// Session represents a user session
type Session struct {
	id   string
	data map[string]string
}

// ID returns this session's id
func (s *Session) ID() string {
	return s.id
}

// Get returns the given session key's value if it exists
func (s *Session) Get(key string) (string, error) {

	if d, ok := s.data[key]; ok {
		return d, nil
	}

	return "", ErrKeyDoesNotExist

}

// Set sets the given key to the given value for this session
func (s *Session) Set(key, val string) error {
	s.data[key] = val
	return nil
}

// Drop drops the given key from the session data if it exists
func (s *Session) Drop(key string) error {

	if _, ok := s.data[key]; ok {
		delete(s.data, key)
		return nil
	}

	return ErrKeyDoesNotExist
}
