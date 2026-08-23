package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type Remote struct {
	endpoint    *url.URL
	client      *http.Client
	maxResponse int64
}

func NewRemote(endpoint string, client *http.Client, maximumResponseBytes int64) (*Remote, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || client == nil || client.Timeout <= 0 || maximumResponseBytes <= 0 {
		return nil, errors.New("invalid remote audit configuration")
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/") + "/v1/events"
	return &Remote{endpoint: parsed, client: client, maxResponse: maximumResponseBytes}, nil
}

func (r *Remote) Write(event Event) error {
	if err := validateEvent(event); err != nil {
		return err
	}
	body, err := json.Marshal(event)
	if err != nil {
		return errors.New("encode audit event")
	}
	request, err := http.NewRequest(http.MethodPost, r.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return errors.New("create audit request")
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := r.client.Do(request)
	if err != nil {
		return errors.New("audit collector unavailable")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
	if response.StatusCode != http.StatusCreated {
		return errors.New("audit collector rejected event")
	}
	return nil
}

func (r *Remote) ListByUser(ctx context.Context, userID string) ([]Record, error) {
	var records []Record
	if err := r.query(ctx, r.endpoint.String(), userID, &records); err != nil {
		return nil, err
	}
	return records, nil
}

func (r *Remote) GetByUser(ctx context.Context, userID, recordID string) (Record, error) {
	if strings.TrimSpace(recordID) == "" || strings.Contains(recordID, "/") {
		return Record{}, ErrRecordMissing
	}
	var record Record
	if err := r.query(ctx, r.endpoint.String()+"/"+url.PathEscape(recordID), userID, &record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (r *Remote) query(ctx context.Context, endpoint, userID string, target any) error {
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(userID) != userID {
		return errors.New("authenticated audit user is required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return errors.New("create audit query")
	}
	request.Header.Set("X-WAI-User-ID", userID)
	response, err := r.client.Do(request)
	if err != nil {
		return errors.New("audit collector unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return ErrRecordMissing
	}
	if response.StatusCode != http.StatusOK {
		return errors.New("audit collector rejected query")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, r.maxResponse+1))
	if err != nil || int64(len(body)) > r.maxResponse || json.Unmarshal(body, target) != nil {
		return errors.New("invalid audit collector response")
	}
	return nil
}
