// This upstream accepts only generated demonstration credentials. It never
// prints or returns them. It is not part of the production runtime image.
package main

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"time"
)

func main() {
	expected := "Bearer " + os.Getenv("DEMO_UPSTREAM_TOKEN")
	s := &http.Server{Addr: ":8081", ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(expected)) != 1 {
			w.WriteHeader(401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"token_injected": true, "path": r.URL.Path, "method": r.Method, "issues": []string{"A policy-scoped request reached the upstream."}})
	})}
	if s.ListenAndServe() != http.ErrServerClosed {
		os.Exit(1)
	}
}
