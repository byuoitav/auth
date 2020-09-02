package cookiestore

type Option func(*Store)

// WithKey allows the client to overwrite the default random signing key
func WithKey(k []byte) Option {
	return func(s *Store) {
		s.key = k
	}
}

// WithTTL allows the client to set the TTL (in minutes) of the cookie session.
// The TTL is intented to be used as a "inactivity timeout" and will be updated
// each time the session is loaded.
func WithTTL(ttl int) Option {
	return func(s *Store) {
		s.ttl = ttl
	}
}

// WithMaxAge allows the client to set the maximum duration of a session
// regardless of activity. The age is in minutes.
func WithMaxAge(maxAge int) Option {
	return func(s *Store) {
		s.maxAge = maxAge
	}
}
