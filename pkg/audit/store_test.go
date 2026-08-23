package audit

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func validRecord(id, user string) Record {
	return Record{ID: id, TransactionID: "tx-1", UserID: user, EventType: MCPToolAllowed, Target: "demo:system.whoami", Decision: "allow", ReasonCode: "policy_allowed", AgentID: "urn:agent:web-app", TransactionWorkloadID: "spiffe://example.org/agent/web-app", SubmittingSPIFFEID: "spiffe://example.org/gateway/mcp"}
}

func TestStoreBoundsRetentionAndUserOwnership(t *testing.T) {
	now := time.Now().UTC()
	store, err := NewStore(StoreConfig{MaximumRecords: 2, MaximumFieldBytes: 200, Retention: time.Minute, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	first, _ := store.Add(validRecord("one", "user-a"))
	_, _ = store.Add(validRecord("two", "user-b"))
	_, _ = store.Add(validRecord("three", "user-a"))
	if _, err := store.GetByUser("user-a", first.ID); !errors.Is(err, ErrRecordMissing) {
		t.Fatal("capacity bound did not evict the oldest record")
	}
	if _, err := store.GetByUser("user-b", "three"); !errors.Is(err, ErrRecordMissing) {
		t.Fatal("cross-user record lookup succeeded")
	}
	if records := store.ListByUser("user-a"); len(records) != 1 || records[0].ID != "three" {
		t.Fatalf("unexpected user-filtered records: %#v", records)
	}
	now = now.Add(2 * time.Minute)
	if records := store.ListByUser("user-a"); len(records) != 0 {
		t.Fatal("expired records remained queryable")
	}
}

func TestStoreRejectsOversizedAndCredentialShapedFields(t *testing.T) {
	store, _ := NewStore(StoreConfig{MaximumRecords: 2, MaximumFieldBytes: 256, Retention: time.Minute})
	tests := []Record{validRecord(strings.Repeat("x", 257), "user"), validRecord("id", "Bearer secret-value"), validRecord("id", "aaaabbbbccccdddd.eeeeffffgggghhhh.iiiijjjjkkkkllll")}
	for _, record := range tests {
		if _, err := store.Add(record); !errors.Is(err, ErrInvalidRecord) {
			t.Fatalf("unsafe audit field accepted: %#v", record)
		}
	}
}

func TestStoreRejectsUnboundedConfigurationAndDuplicateIDs(t *testing.T) {
	for _, config := range []StoreConfig{
		{MaximumRecords: 100_001, MaximumFieldBytes: 1, Retention: time.Minute},
		{MaximumRecords: 1, MaximumFieldBytes: (64 << 10) + 1, Retention: time.Minute},
		{MaximumRecords: 1, MaximumFieldBytes: 1, Retention: 24*time.Hour + time.Second},
	} {
		if _, err := NewStore(config); !errors.Is(err, ErrInvalidRecord) {
			t.Fatal("unbounded audit store configuration accepted")
		}
	}
	store, _ := NewStore(StoreConfig{MaximumRecords: 2, MaximumFieldBytes: 256, Retention: time.Minute})
	_, _ = store.Add(validRecord("duplicate", "user"))
	if _, err := store.Add(validRecord("duplicate", "user")); !errors.Is(err, ErrInvalidRecord) {
		t.Fatal("ambiguous duplicate audit record ID accepted")
	}
}

type failingSink struct{ err error }

func (s failingSink) Write(Event) error { return s.err }

func TestFanoutFailsClosedWhenRequiredCollectorFails(t *testing.T) {
	fanout, _ := NewFanout(failingSink{}, failingSink{err: errors.New("collector down")})
	if err := fanout.Write(Event{Type: MCPToolAllowed}); err == nil {
		t.Fatal("required collector failure was ignored")
	}
}
