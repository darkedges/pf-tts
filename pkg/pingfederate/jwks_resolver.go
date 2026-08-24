package pingfederate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

var ErrJWKSResolution = errors.New("JWKS key resolution failed")

type JWKSKeyResolver struct {
	endpoint string
	client   *http.Client
	maximum  int64
}

func NewJWKSKeyResolver(endpoint string, client *http.Client, maximumBytes int64) (*JWKSKeyResolver, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || client == nil || client.Timeout <= 0 || maximumBytes <= 0 {
		return nil, fmt.Errorf("%w: invalid configuration", ErrJWKSResolution)
	}
	clone := *client
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &JWKSKeyResolver{endpoint: parsed.String(), client: &clone, maximum: maximumBytes}, nil
}

func (r *JWKSKeyResolver) ResolveVerificationKey(ctx context.Context, keyID string) (any, error) {
	if strings.TrimSpace(keyID) == "" || len(keyID) > 256 || strings.TrimSpace(keyID) != keyID {
		return nil, fmt.Errorf("%w: invalid key ID", ErrJWKSResolution)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: request creation failed", ErrJWKSResolution)
	}
	req.Header.Set("Accept", "application/json")
	response, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: endpoint request failed", ErrJWKSResolution)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: endpoint rejected request", ErrJWKSResolution)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, r.maximum+1))
	if err != nil || int64(len(body)) > r.maximum || rejectDuplicateJSON(body) != nil {
		return nil, fmt.Errorf("%w: invalid response", ErrJWKSResolution)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil || len(set.Keys) == 0 {
		return nil, fmt.Errorf("%w: invalid response", ErrJWKSResolution)
	}
	matches := set.Key(keyID)
	if len(matches) != 1 || matches[0].Key == nil {
		return nil, fmt.Errorf("%w: unknown or ambiguous key ID", ErrJWKSResolution)
	}
	return matches[0].Key, nil
}

func rejectDuplicateJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSON(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func scanJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid object key")
			}
			if _, exists := seen[key]; exists {
				return errors.New("duplicate object key")
			}
			seen[key] = struct{}{}
			if err := scanJSON(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := scanJSON(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("invalid JSON delimiter")
	}
}
