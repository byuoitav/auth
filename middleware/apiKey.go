package middleware

import (
	"context"
	"net/http"
)

const _avAPIKeyHeader = "x-av-access-key"

type contextKey int

const _avAPIKeyContextKey = 0

// AVAPIKeymiddleware simply looks at the expected API Key header for AV products
// and if an API Key is found it is placed into the context of the request
func AVAPIKeyMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiKey := r.Header.Get(_avAPIKeyHeader)

			// If the header is empty then continue
			if apiKey == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Put the api key found into the context and continue
			ctx := r.Context()
			ctx = context.WithValue(ctx, _avAPIKeyContextKey, apiKey)
			ctx = context.WithValue(ctx, "passed-auth-check", "true")
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		})
	}
}

// GetAVAPIKey gets an AV API key from a context if it exists
func GetAVAPIKey(ctx context.Context) (string, bool) {
	apiKey, ok := ctx.Value(_avAPIKeyContextKey).(string)
	return apiKey, ok
}
