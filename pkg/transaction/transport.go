package transaction

import (
	"errors"
	"net/http"
	"strings"
)

const TxnTokenHeader = "Txn-Token"

var ErrTxnTokenTransport = errors.New("transaction token transport rejected")

// ExtractTxnToken returns the single strict Txn-Token field value. The caller
// must cryptographically verify the returned compact token before using it.
func ExtractTxnToken(header http.Header, maximumBytes int) (string, error) {
	if header == nil || maximumBytes <= 0 || headerPresent(header, "Authorization") {
		return "", ErrTxnTokenTransport
	}
	values := header.Values(TxnTokenHeader)
	if len(values) != 1 || !validCompactTransportValue(values[0], maximumBytes) {
		return "", ErrTxnTokenTransport
	}
	return values[0], nil
}

// SetTxnToken writes one strict field only when the destination has no existing
// authorization credential. It never replaces or appends ambiguous state.
func SetTxnToken(header http.Header, raw string, maximumBytes int) error {
	if header == nil || maximumBytes <= 0 || headerPresent(header, "Authorization") || headerPresent(header, TxnTokenHeader) || !validCompactTransportValue(raw, maximumBytes) {
		return ErrTxnTokenTransport
	}
	header.Set(TxnTokenHeader, raw)
	return nil
}

func headerPresent(header http.Header, name string) bool {
	for key := range header {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

func validCompactTransportValue(value string, maximumBytes int) bool {
	if value == "" || len(value) > maximumBytes || strings.TrimSpace(value) != value || strings.ContainsAny(value, " \t\r\n,") || strings.Count(value, ".") != 2 {
		return false
	}
	parts := strings.Split(value, ".")
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, character := range part {
			if !((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' || character == '_') {
				return false
			}
		}
	}
	return true
}
