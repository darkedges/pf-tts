package audit

import (
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidRecord = errors.New("invalid audit record")
	ErrRecordMissing = errors.New("audit record not found")
	jwtShape         = regexp.MustCompile(`(^|[^A-Za-z0-9_-])[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}($|[^A-Za-z0-9_-])`)
)

// Record is a typed, credential-safe interaction summary. It intentionally
// has no arbitrary headers, arguments, or request/response body fields.
type Record struct {
	ID                      string         `json:"id"`
	Sequence                uint64         `json:"sequence"`
	Timestamp               time.Time      `json:"timestamp"`
	TransactionID           string         `json:"transaction_id"`
	UserID                  string         `json:"user_id"`
	EventType               string         `json:"event_type"`
	Target                  string         `json:"target,omitempty"`
	Decision                string         `json:"decision,omitempty"`
	ReasonCode              string         `json:"reason_code,omitempty"`
	AgentID                 string         `json:"agent_id,omitempty"`
	TransactionWorkloadID   string         `json:"transaction_workload_id,omitempty"`
	ImmediateCallerSPIFFEID string         `json:"immediate_caller_spiffe_id,omitempty"`
	SubmittingSPIFFEID      string         `json:"submitting_spiffe_id"`
	ProtocolMethod          string         `json:"protocol_method,omitempty"`
	Tool                    string         `json:"tool,omitempty"`
	Purpose                 string         `json:"purpose,omitempty"`
	ResponseStatus          int            `json:"response_status,omitempty"`
	ResultType              string         `json:"result_type,omitempty"`
	DurationMillis          int64          `json:"duration_ms,omitempty"`
	Token                   *TokenEvidence `json:"verified_transaction_token,omitempty"`
}

type StoreConfig struct {
	MaximumRecords    int
	MaximumFieldBytes int
	Retention         time.Duration
	Now               func() time.Time
}

type Store struct {
	config   StoreConfig
	mu       sync.RWMutex
	records  []Record
	sequence uint64
}

func NewStore(config StoreConfig) (*Store, error) {
	if config.MaximumRecords <= 0 || config.MaximumRecords > 100_000 || config.MaximumFieldBytes <= 0 || config.MaximumFieldBytes > 64<<10 || config.Retention <= 0 || config.Retention > 24*time.Hour {
		return nil, ErrInvalidRecord
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Store{config: config, records: make([]Record, 0, config.MaximumRecords)}, nil
}

func (s *Store) Add(record Record) (Record, error) {
	if err := s.validate(record); err != nil {
		return Record{}, err
	}
	record.Token = cloneTokenEvidence(record.Token)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.config.Now().UTC()
	s.purgeLocked(now)
	for _, existing := range s.records {
		if existing.ID == record.ID {
			return Record{}, ErrInvalidRecord
		}
	}
	s.sequence++
	record.Sequence = s.sequence
	record.Timestamp = now
	if len(s.records) == s.config.MaximumRecords {
		copy(s.records, s.records[1:])
		s.records[len(s.records)-1] = record
	} else {
		s.records = append(s.records, record)
	}
	return cloneRecord(record), nil
}

func (s *Store) ListByUser(userID string) []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked(s.config.Now().UTC())
	result := make([]Record, 0)
	for _, record := range s.records {
		if record.UserID == userID {
			result = append(result, cloneRecord(record))
		}
	}
	return result
}

func (s *Store) GetByUser(userID, recordID string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked(s.config.Now().UTC())
	for _, record := range s.records {
		if record.ID == recordID && record.UserID == userID {
			return cloneRecord(record), nil
		}
	}
	return Record{}, ErrRecordMissing
}

func (s *Store) validate(record Record) error {
	required := []string{record.ID, record.TransactionID, record.UserID, record.EventType, record.SubmittingSPIFFEID}
	for _, value := range required {
		if strings.TrimSpace(value) == "" {
			return ErrInvalidRecord
		}
	}
	if _, ok := allowedEventTypes[record.EventType]; !ok || record.ResponseStatus != 0 && (record.ResponseStatus < 100 || record.ResponseStatus > 599) || record.DurationMillis < 0 || record.DurationMillis > int64((24*time.Hour)/time.Millisecond) {
		return ErrInvalidRecord
	}
	if record.Decision != "" && record.Decision != "allow" && record.Decision != "deny" {
		return ErrInvalidRecord
	}
	fields := []string{record.ID, record.TransactionID, record.UserID, record.EventType, record.Target, record.Decision, record.ReasonCode, record.AgentID, record.TransactionWorkloadID, record.ImmediateCallerSPIFFEID, record.SubmittingSPIFFEID, record.ProtocolMethod, record.Tool, record.Purpose, record.ResultType}
	for _, value := range fields {
		if len(value) > s.config.MaximumFieldBytes || credentialShaped(value) {
			return ErrInvalidRecord
		}
	}
	if validateTokenEvidence(record.Token, s.config.MaximumFieldBytes) != nil {
		return ErrInvalidRecord
	}
	return nil
}

func cloneRecord(record Record) Record {
	record.Token = cloneTokenEvidence(record.Token)
	return record
}

var allowedEventTypes = map[string]struct{}{
	TransactionExchangeRequested: {}, TransactionExchangeSucceeded: {}, TransactionExchangeFailed: {},
	TransactionVerifySucceeded: {}, TransactionVerifyFailed: {}, MCPToolRequested: {}, MCPToolAllowed: {},
	MCPToolDenied: {}, DownstreamRequest: {},
}

func (s *Store) purgeLocked(now time.Time) {
	cutoff := now.Add(-s.config.Retention)
	first := 0
	for first < len(s.records) && s.records[first].Timestamp.Before(cutoff) {
		first++
	}
	if first > 0 {
		copy(s.records, s.records[first:])
		s.records = s.records[:len(s.records)-first]
	}
}

func credentialShaped(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "bearer ") || strings.Contains(lower, "access_token") ||
		strings.Contains(lower, "client_secret") || strings.Contains(lower, "refresh_token") ||
		strings.Contains(lower, "authorization_code") || strings.Contains(lower, "private key") || strings.Contains(lower, "private_key") ||
		jwtShape.MatchString(value)
}
