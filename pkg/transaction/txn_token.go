package transaction

import "time"

const TxnTokenJOSEType = "txntoken+jwt"

type TxnTokenClaims struct {
	Issuer               string
	Subject              string
	Audience             string
	TransactionID        string
	Scope                []string
	RequestingWorkloadID string
	TransactionContext   TransactionContext
	RequestContext       *RequestContext
	JWTID                string
	IssuedAt             time.Time
	ExpiresAt            time.Time
}

type TransactionContext struct {
	WAI WAITransactionContext
}

type WAITransactionContext struct {
	Version int
	Agent   WAIAgentContext
	Target  string
	Tool    string
}

type WAIAgentContext struct {
	ID         string
	InstanceID string
	WorkloadID string
}

type RequestContext struct {
	AuthenticationMethod string
}
