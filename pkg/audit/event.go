package audit

import (
	"encoding/json"
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
	Type                    string    `json:"type"`
	Timestamp               time.Time `json:"timestamp"`
	TransactionID           string    `json:"transaction_id,omitempty"`
	UserID                  string    `json:"user_id,omitempty"`
	AgentID                 string    `json:"agent_id,omitempty"`
	TransactionWorkloadID   string    `json:"transaction_workload_id,omitempty"`
	ImmediateCallerSPIFFEID string    `json:"immediate_caller_spiffe_id,omitempty"`
	Target                  string    `json:"target,omitempty"`
	Decision                string    `json:"decision,omitempty"`
	ReasonCode              string    `json:"reason_code,omitempty"`
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	return s.encoder.Encode(event)
}
