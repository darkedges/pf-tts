package audit

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestRemoteSinkSendsOnlyTypedEventAndFailsOnRejection(t *testing.T) {
	seenAuthorization := ""
	client := &http.Client{Timeout: time.Second, Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		seenAuthorization = request.Header.Get("Authorization")
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader("unavailable")), Header: make(http.Header)}, nil
	})}
	remote, err := NewRemote("https://audit.example", client, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(Event{Type: MCPToolAllowed, TransactionID: "tx", UserID: "user"}); err == nil {
		t.Fatal("collector rejection was ignored")
	}
	if seenAuthorization != "" {
		t.Fatal("remote audit request propagated a bearer credential")
	}
}

func TestRemoteRejectsInsecureEndpointAndMissingUser(t *testing.T) {
	client := &http.Client{Timeout: time.Second}
	if _, err := NewRemote("http://audit.example", client, 1024); err == nil {
		t.Fatal("insecure collector endpoint accepted")
	}
	remote, _ := NewRemote("https://audit.example", client, 1024)
	if _, err := remote.ListByUser(t.Context(), ""); err == nil || errors.Is(err, ErrRecordMissing) {
		t.Fatalf("missing authenticated query user accepted: %v", err)
	}
}
