package webapp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEmbeddedUIHasSecureAccessibleResponsiveStructure(t *testing.T) {
	flow := newFlow(t)
	tests := []struct {
		path, contentType string
		required          []string
	}{
		{"/", "text/html", []string{`class="workspace"`, `class="interaction-panel"`, `class="audit-panel"`, `href="#workspace"`, `aria-live="polite"`, `Sign in with PingFederate`, `src="/app.js"`}},
		{"/app.css", "text/css", []string{"grid-template-columns: minmax(0, 2fr) minmax(20rem, 1fr)", "@media (max-width: 820px)", ":focus-visible", "prefers-reduced-motion"}},
		{"/app.js", "text/javascript", []string{"textContent", "replaceChildren", "same-origin", "X-CSRF-Token", "encodeURIComponent", "No verified interactions yet"}},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			flow.handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://app.example"+test.path, nil))
			if response.Code != http.StatusOK || !strings.HasPrefix(response.Header().Get("Content-Type"), test.contentType) {
				t.Fatalf("asset response = %d %q", response.Code, response.Header().Get("Content-Type"))
			}
			for _, required := range test.required {
				if !strings.Contains(response.Body.String(), required) {
					t.Fatalf("asset missing %q", required)
				}
			}
			csp := response.Header().Get("Content-Security-Policy")
			if !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
				t.Fatalf("unsafe CSP: %q", csp)
			}
			if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Frame-Options") != "DENY" {
				t.Fatal("UI response missing security headers")
			}
		})
	}
}

func TestBrowserAssetsContainNoCredentialStorageOrUnsafeRendering(t *testing.T) {
	javascript, err := staticFiles.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"localStorage", "sessionStorage", "innerHTML", "outerHTML", "document.write", "console.", "Authorization", "access_token", "client_secret", "Bearer "} {
		if strings.Contains(string(javascript), forbidden) {
			t.Fatalf("browser asset contains unsafe capability or credential field %q", forbidden)
		}
	}
}
