package session

import "net/http"

// Session represents a user session and all the data pertinent to the user's session
type Session struct {
	// ID is primarily used by different session stores to keep track of the session
	// this value is expected to be unique across all session for the application
	// globally. As such, the client in most cases should *not* set this to any
	// value, instead allowing the backing store to populate the ID accordingly
	ID string

	// Values provides arbitrary value storage for the client to keep track of
	// data regarding the session
	Values map[string]interface{}

	// IsNew is set to true if the session was freshly created for this request
	IsNew bool

	// store is the backing store that provides storage for this session
	store Store

	// name is the client-settable name for the session. This name is entirely
	// up to the client to set and may be used to track different types of
	// sessions in the request
	name string
}

func NewSession(store Store, name string) *Session {
	return &Session{
		Values: make(map[string]interface{}),
		IsNew:  true,
		store:  store,
		name:   name,
	}
}

func (s *Session) Save(r *http.Request, w http.ResponseWriter) error {
	return s.store.Save(r, w, s)
}

func (s *Session) Name() string {
	return s.name
}
