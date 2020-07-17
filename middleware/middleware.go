package middleware

import (
	"net/http"
)

// Authenticated returns true if the given request has already been authenticated
func Authenticated(r *http.Request) bool {

	pass := r.Context().Value("passed-auth-check")
	if pass != nil {
		if v, ok := pass.(string); ok {
			if v == "true" {
				return true
			}
		}
	}

	return false
}
