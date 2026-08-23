package audit

import (
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"
)

const (
	TransactionExchangeRequested = "transaction.exchange.requested"
	TransactionExchangeSucceeded = "transaction.exchange.succeeded"
	TransactionExchangeFailed    = "transaction.exchange.failed"
	TransactionVerifySucceeded   = "transaction.verify.succeeded"
	TransactionVerifyFailed      = "transaction.verify.failed"
	MCPToolRequested             = "mcp.tool.requested"
	MCPToolAllowed               = "mcp.tool.allowed"
	MCPToolDenied                = "mcp.tool.denied"
	DownstreamRequest            = "downstream.request"
)

type Event struct {
	Type                    string         `json:"type"`
	Timestamp               time.Time      `json:"timestamp"`
	TransactionID           string         `json:"transaction_id,omitempty"`
	UserID                  string         `json:"user_id,omitempty"`
	AgentID                 string         `json:"agent_id,omitempty"`
	TransactionWorkloadID   string         `json:"transaction_workload_id,omitempty"`
	ImmediateCallerSPIFFEID string         `json:"immediate_caller_spiffe_id,omitempty"`
	Target                  string         `json:"target,omitempty"`
	Decision                string         `json:"decision,omitempty"`
	ReasonCode              string         `json:"reason_code,omitempty"`
	ProtocolMethod          string         `json:"protocol_method,omitempty"`
	Tool                    string         `json:"tool,omitempty"`
	Purpose                 string         `json:"purpose,omitempty"`
	ResponseStatus          int            `json:"response_status,omitempty"`
	ResultType              string         `json:"result_type,omitempty"`
	DurationMillis          int64          `json:"duration_ms,omitempty"`
	Token                   *TokenEvidence `json:"verified_transaction_token,omitempty"`
}

type Sink interface {
	Write(Event) error
}

type JSONSink struct {
	mu      sync.Mutex
	encoder *json.Encoder
}

func NewJSONSink(writer io.Writer) *JSONSink { return &JSONSink{encoder: json.NewEncoder(writer)} }
func (s *JSONSink) Write(event Event) error {
	if err := validateEvent(event); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	return s.encoder.Encode(event)
}

func validateEvent(event Event) error {
	if _, ok := allowedEventTypes[event.Type]; !ok || event.ResponseStatus != 0 && (event.ResponseStatus < 100 || event.ResponseStatus > 599) || event.DurationMillis < 0 || event.DurationMillis > int64((24*time.Hour)/time.Millisecond) {
		return errors.New("invalid audit event")
	}
	if event.Decision != "" && event.Decision != "allow" && event.Decision != "deny" {
		return errors.New("invalid audit event")
	}
	fields := []string{event.Type, event.TransactionID, event.UserID, event.AgentID, event.TransactionWorkloadID, event.ImmediateCallerSPIFFEID, event.Target, event.Decision, event.ReasonCode, event.ProtocolMethod, event.Tool, event.Purpose, event.ResultType}
	for _, value := range fields {
		if len(value) > 64<<10 || credentialShaped(value) {
			return errors.New("invalid audit event")
		}
	}
	if validateTokenEvidence(event.Token, 64<<10) != nil {
		return errors.New("invalid audit event")
	}
	return nil
}
