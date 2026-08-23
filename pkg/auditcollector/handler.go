package auditcollector

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"example.com/workload-agent-identity/pkg/audit"
	"example.com/workload-agent-identity/pkg/middleware"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type Config struct {
	Store             *audit.Store
	AllowedSubmitters []string
	QueryCaller       string
	MaximumBodyBytes  int64
	Random            io.Reader
}

type Handler struct {
	store       *audit.Store
	submitters  map[string]struct{}
	queryCaller string
	maxBody     int64
	random      io.Reader
	mux         *http.ServeMux
}

func New(config Config) (*Handler, error) {
	if config.Store == nil || len(config.AllowedSubmitters) == 0 || len(config.AllowedSubmitters) > 100 || strings.TrimSpace(config.QueryCaller) == "" || config.MaximumBodyBytes <= 0 || config.MaximumBodyBytes > 1<<20 {
		return nil, errors.New("invalid audit collector configuration")
	}
	submitters := make(map[string]struct{}, len(config.AllowedSubmitters))
	for _, caller := range config.AllowedSubmitters {
		if strings.TrimSpace(caller) != caller || caller == "" {
			return nil, errors.New("invalid audit collector submitter")
		}
		if _, err := spiffeid.FromString(caller); err != nil {
			return nil, errors.New("invalid audit collector submitter")
		}
		if _, duplicate := submitters[caller]; duplicate {
			return nil, errors.New("duplicate audit collector submitter")
		}
		submitters[caller] = struct{}{}
	}
	if _, err := spiffeid.FromString(config.QueryCaller); err != nil {
		return nil, errors.New("invalid audit collector query caller")
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	h := &Handler{store: config.Store, submitters: submitters, queryCaller: config.QueryCaller, maxBody: config.MaximumBodyBytes, random: config.Random, mux: http.NewServeMux()}
	h.mux.HandleFunc("POST /v1/events", h.submit)
	h.mux.HandleFunc("GET /v1/events", h.list)
	h.mux.HandleFunc("GET /v1/events/{id}", h.get)
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) submit(w http.ResponseWriter, r *http.Request) {
	caller, err := middleware.ImmediateCallerSPIFFEID(r.TLS)
	if err != nil {
		h.deny(w)
		return
	}
	if _, ok := h.submitters[caller]; !ok {
		h.deny(w)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		h.invalid(w)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, h.maxBody+1))
	if err != nil || int64(len(body)) > h.maxBody {
		h.invalid(w)
		return
	}
	var event audit.Event
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&event) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		h.invalid(w)
		return
	}
	id, err := h.randomID()
	if err != nil {
		h.unavailable(w)
		return
	}
	record := audit.Record{ID: id, TransactionID: event.TransactionID, UserID: event.UserID, EventType: event.Type, Target: event.Target, Decision: event.Decision, ReasonCode: event.ReasonCode, AgentID: event.AgentID, TransactionWorkloadID: event.TransactionWorkloadID, ImmediateCallerSPIFFEID: event.ImmediateCallerSPIFFEID, SubmittingSPIFFEID: caller, ProtocolMethod: event.ProtocolMethod, Tool: event.Tool, Purpose: event.Purpose, ResponseStatus: event.ResponseStatus, ResultType: event.ResultType, DurationMillis: event.DurationMillis}
	stored, err := h.store.Add(record)
	if err != nil {
		h.invalid(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(struct {
		ID string `json:"id"`
	}{ID: stored.ID})
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	user, ok := h.queryUser(w, r)
	if !ok {
		return
	}
	h.writeJSON(w, h.store.ListByUser(user))
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	user, ok := h.queryUser(w, r)
	if !ok {
		return
	}
	record, err := h.store.GetByUser(user, r.PathValue("id"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	h.writeJSON(w, record)
}

func (h *Handler) queryUser(w http.ResponseWriter, r *http.Request) (string, bool) {
	caller, err := middleware.ImmediateCallerSPIFFEID(r.TLS)
	user := strings.TrimSpace(r.Header.Get("X-WAI-User-ID"))
	if err != nil || caller != h.queryCaller || user == "" || user != r.Header.Get("X-WAI-User-ID") {
		h.deny(w)
		return "", false
	}
	return user, true
}

func (h *Handler) writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func (h *Handler) randomID() (string, error) {
	value := make([]byte, 24)
	if _, err := io.ReadFull(h.random, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func (h *Handler) deny(w http.ResponseWriter) { http.Error(w, "forbidden", http.StatusForbidden) }
func (h *Handler) invalid(w http.ResponseWriter) {
	http.Error(w, "invalid audit event", http.StatusBadRequest)
}
func (h *Handler) unavailable(w http.ResponseWriter) {
	http.Error(w, "audit unavailable", http.StatusInternalServerError)
}
