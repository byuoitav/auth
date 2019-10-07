package middleware

import (
	"net/http"

	"github.com/byuoitav/common/log"
)

// Authenticated returns true if the given request has already been authenticated
func Authenticated(r *http.Request) bool {

	pass := r.Context().Value("passed-auth-check")
	if pass != nil {
		if v, ok := pass.(string); ok {
			if v == "true" {
				log.L.Debugf("Request has already been authenticated")
				return true
			}
		}
	}

	return false
}
