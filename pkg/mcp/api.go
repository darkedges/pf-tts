package mcp

import (
	"encoding/json"
	"example.com/workload-agent-identity/pkg/identity"
	"example.com/workload-agent-identity/pkg/middleware"
	"net/http"
	"strings"
)

func DemoAPIHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, ok := identity.FromContext(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"customer_id": "customer-123", "name": "Demo Customer", "transaction_id": v.Transaction.ID})
	})
}

func StrictDemoAPIHandler(target, tool string) (http.Handler, error) {
	if strings.TrimSpace(target) == "" || strings.TrimSpace(tool) == "" {
		return nil, ErrStrictTransactionDenied
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if headerExists(r.Header, "Authorization") || !signedToolMatches(r.Context(), target, tool) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		value, identityOK := identity.FromContext(r.Context())
		_, tokenOK := middleware.VerifiedTransactionToken(r.Context())
		if !identityOK || !tokenOK {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(struct {
			TransactionID string `json:"transaction_id"`
		}{TransactionID: value.Transaction.ID})
	}), nil
}
