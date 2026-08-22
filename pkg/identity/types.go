package identity

import (
	"errors"
	"strings"
)

var ErrInvalidIdentity = errors.New("invalid identity")

type UserIdentity struct {
	ID string
}

type AgentIdentity struct {
	ID         string
	InstanceID string
}

type WorkloadIdentity struct {
	SPIFFEID string
}

type TransactionIdentity struct {
	ID      string
	Purpose string
}

type AuthorizationContext struct {
	Scope []string
}

type RequestIdentityContext struct {
	User             UserIdentity
	Agent            AgentIdentity
	OriginalWorkload WorkloadIdentity
	ImmediateCaller  WorkloadIdentity
	Transaction      TransactionIdentity
	Authorization    AuthorizationContext
}

func NewAgentIdentity(id, instanceID string) (AgentIdentity, error) {
	id = strings.TrimSpace(id)
	instanceID = strings.TrimSpace(instanceID)
	if id == "" || instanceID == "" {
		return AgentIdentity{}, ErrInvalidIdentity
	}
	return AgentIdentity{ID: id, InstanceID: instanceID}, nil
}

func NewLogicalAgentIdentity(id string) (AgentIdentity, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return AgentIdentity{}, ErrInvalidIdentity
	}
	return AgentIdentity{ID: id}, nil
}

func NewUserIdentity(id string) (UserIdentity, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return UserIdentity{}, ErrInvalidIdentity
	}
	return UserIdentity{ID: id}, nil
}

func NewWorkloadIdentity(spiffeID string) (WorkloadIdentity, error) {
	spiffeID = strings.TrimSpace(spiffeID)
	if !strings.HasPrefix(spiffeID, "spiffe://") || len(spiffeID) == len("spiffe://") {
		return WorkloadIdentity{}, ErrInvalidIdentity
	}
	return WorkloadIdentity{SPIFFEID: spiffeID}, nil
}

func NewTransactionIdentity(id, purpose string) (TransactionIdentity, error) {
	id = strings.TrimSpace(id)
	purpose = strings.TrimSpace(purpose)
	if id == "" || purpose == "" {
		return TransactionIdentity{}, ErrInvalidIdentity
	}
	return TransactionIdentity{ID: id, Purpose: purpose}, nil
}

func NewAuthorizationContext(scopes []string) (AuthorizationContext, error) {
	if len(scopes) == 0 {
		return AuthorizationContext{}, ErrInvalidIdentity
	}
	clean := make([]string, len(scopes))
	for i, scope := range scopes {
		clean[i] = strings.TrimSpace(scope)
		if clean[i] == "" {
			return AuthorizationContext{}, ErrInvalidIdentity
		}
	}
	return AuthorizationContext{Scope: clean}, nil
}

func NewRequestIdentityContext(user UserIdentity, agent AgentIdentity, originalWorkload, immediateCaller WorkloadIdentity, transaction TransactionIdentity, authorization AuthorizationContext) (RequestIdentityContext, error) {
	if user.ID == "" || agent.ID == "" || agent.InstanceID == "" || originalWorkload.SPIFFEID == "" || immediateCaller.SPIFFEID == "" || transaction.ID == "" || transaction.Purpose == "" || len(authorization.Scope) == 0 {
		return RequestIdentityContext{}, ErrInvalidIdentity
	}
	return RequestIdentityContext{
		User: user, Agent: agent, OriginalWorkload: originalWorkload,
		ImmediateCaller: immediateCaller, Transaction: transaction, Authorization: authorization,
	}, nil
}
