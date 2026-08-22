package mcp

import (
	"encoding/json"
	"example.com/workload-agent-identity/pkg/identity"
	"net/http"
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
