package transaction

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

const transportToken = "header.payload.signature"

func TestExtractTxnTokenAcceptsExactlyOneStrictField(t *testing.T) {
	header := make(http.Header)
	header.Set(TxnTokenHeader, transportToken)
	got, err := ExtractTxnToken(header, 1024)
	if err != nil || got != transportToken {
		t.Fatalf("ExtractTxnToken() = %q, %v", got, err)
	}
}

func TestExtractTxnTokenRejectsAmbiguousAndMalformedTransport(t *testing.T) {
	tests := map[string]func(http.Header){
		"missing":             func(http.Header) {},
		"legacy bearer":       func(h http.Header) { h.Set("Authorization", "Bearer legacy-secret") },
		"empty authorization": func(h http.Header) { h["Authorization"] = []string{""} },
		"duplicate": func(h http.Header) {
			h.Add(TxnTokenHeader, transportToken)
			h.Add(TxnTokenHeader, transportToken)
		},
		"comma folded":       func(h http.Header) { h.Set(TxnTokenHeader, transportToken+","+transportToken) },
		"leading whitespace": func(h http.Header) { h.Set(TxnTokenHeader, " "+transportToken) },
		"control":            func(h http.Header) { h[TxnTokenHeader] = []string{"header.payload.sign\rature"} },
		"one segment":        func(h http.Header) { h.Set(TxnTokenHeader, "payload") },
		"empty segment":      func(h http.Header) { h.Set(TxnTokenHeader, "header..signature") },
		"invalid alphabet":   func(h http.Header) { h.Set(TxnTokenHeader, "header.pay+load.signature") },
		"oversized":          func(h http.Header) { h.Set(TxnTokenHeader, "header."+strings.Repeat("a", 1018)+".signature") },
	}
	for name, prepare := range tests {
		t.Run(name, func(t *testing.T) {
			header := make(http.Header)
			if name != "missing" {
				header.Set(TxnTokenHeader, transportToken)
			}
			prepare(header)
			if raw, err := ExtractTxnToken(header, 1024); !errors.Is(err, ErrTxnTokenTransport) || raw != "" || strings.Contains(err.Error(), transportToken) {
				t.Fatalf("unsafe transport accepted or leaked: raw=%q err=%v", raw, err)
			}
		})
	}
	if _, err := ExtractTxnToken(http.Header{TxnTokenHeader: []string{transportToken}}, 0); !errors.Is(err, ErrTxnTokenTransport) {
		t.Fatal("non-positive bound accepted")
	}
}

func TestSetTxnTokenWritesOnlyToCleanDestination(t *testing.T) {
	header := make(http.Header)
	if err := SetTxnToken(header, transportToken, 1024); err != nil {
		t.Fatal(err)
	}
	if values := header.Values(TxnTokenHeader); len(values) != 1 || values[0] != transportToken {
		t.Fatalf("unexpected propagated values: %#v", values)
	}

	tests := map[string]http.Header{
		"existing transaction token": {TxnTokenHeader: []string{"other.token.value"}},
		"existing bearer":            {"Authorization": []string{"Bearer legacy-secret"}},
	}
	for name, destination := range tests {
		t.Run(name, func(t *testing.T) {
			before := destination.Clone()
			if err := SetTxnToken(destination, transportToken, 1024); !errors.Is(err, ErrTxnTokenTransport) {
				t.Fatal("credential-bearing destination accepted")
			}
			if strings.Join(destination.Values(TxnTokenHeader), "|") != strings.Join(before.Values(TxnTokenHeader), "|") {
				t.Fatal("destination was mutated on failure")
			}
		})
	}
	if err := SetTxnToken(make(http.Header), "secret", 1024); !errors.Is(err, ErrTxnTokenTransport) || strings.Contains(err.Error(), "secret") {
		t.Fatal("malformed token accepted or leaked")
	}
}
