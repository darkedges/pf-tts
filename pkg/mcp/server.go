package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"example.com/workload-agent-identity/pkg/identity"
	"example.com/workload-agent-identity/pkg/middleware"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type CustomerGetInput struct {
	CustomerID string `json:"customer_id" jsonschema:"customer identifier"`
}
type CustomerGetOutput struct{ CustomerID, Name string }
type WhoAmIOutput struct {
	UserID, AgentID, WorkloadSPIFFEID, ImmediateCallerSPIFFEID, TransactionID, Purpose, APITransactionID string
}

type DemoServerOptions struct {
	APIClient         *http.Client
	APIURL            *url.URL
	strict            bool
	maximumTokenBytes int
}

func NewDemoServerHandler() http.Handler {
	return newDemoServerHandler(DemoServerOptions{})
}

func NewDemoServerHandlerWithAPI(options DemoServerOptions) (http.Handler, error) {
	if options.APIClient == nil || options.APIClient.Timeout <= 0 || options.APIURL == nil || options.APIURL.Scheme != "https" || options.APIURL.Host == "" || options.APIURL.RawQuery != "" {
		return nil, errors.New("fixed HTTPS demo API client configuration required")
	}
	return newDemoServerHandler(options), nil
}

func NewStrictDemoServerHandlerWithAPI(options DemoServerOptions, maximumTokenBytes int) (http.Handler, error) {
	if options.APIClient == nil || options.APIClient.Timeout <= 0 || options.APIURL == nil || options.APIURL.Scheme != "https" || options.APIURL.Host == "" || options.APIURL.RawQuery != "" || maximumTokenBytes <= 0 {
		return nil, errors.New("fixed strict HTTPS demo API client configuration required")
	}
	options.strict = true
	options.maximumTokenBytes = maximumTokenBytes
	return newDemoServerHandler(options), nil
}

func newDemoServerHandler(options DemoServerOptions) http.Handler {
	server := mcpsdk.NewServer(&mcpsdk.Implementation{Name: "demo-mcp-server", Version: "0.1.0"}, nil)
	mcpsdk.AddTool(server, &mcpsdk.Tool{Name: "customer.get", Description: "Get demo customer"}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in CustomerGetInput) (*mcpsdk.CallToolResult, CustomerGetOutput, error) {
		if options.strict && !signedToolMatches(ctx, "demo", "customer.get") {
			return nil, CustomerGetOutput{}, errors.New("strict signed route denied")
		}
		if in.CustomerID == "" {
			return nil, CustomerGetOutput{}, errors.New("customer_id required")
		}
		return &mcpsdk.CallToolResult{}, CustomerGetOutput{CustomerID: in.CustomerID, Name: "Demo Customer"}, nil
	})
	mcpsdk.AddTool(server, &mcpsdk.Tool{Name: "system.whoami", Description: "Return safe verified identity metadata"}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, _ struct{}) (*mcpsdk.CallToolResult, WhoAmIOutput, error) {
		if options.strict && !signedToolMatches(ctx, "demo", "system.whoami") {
			return nil, WhoAmIOutput{}, errors.New("strict signed route denied")
		}
		v, ok := identity.FromContext(ctx)
		if !ok {
			return nil, WhoAmIOutput{}, errors.New("verified identity required")
		}
		output := WhoAmIOutput{UserID: v.User.ID, AgentID: v.Agent.ID, WorkloadSPIFFEID: v.OriginalWorkload.SPIFFEID, ImmediateCallerSPIFFEID: v.ImmediateCaller.SPIFFEID, TransactionID: v.Transaction.ID, Purpose: v.Transaction.Purpose}
		if options.APIClient != nil {
			var apiTransactionID string
			var err error
			if options.strict {
				apiTransactionID, err = callDemoAPIStrict(ctx, options.APIClient, options.APIURL, options.maximumTokenBytes, v.Transaction.ID)
			} else {
				token, ok := middleware.VerifiedTransactionToken(ctx)
				if !ok {
					return nil, WhoAmIOutput{}, errors.New("verified immutable transaction token required")
				}
				apiTransactionID, err = callDemoAPI(ctx, options.APIClient, options.APIURL, token, v.Transaction.ID)
			}
			if err != nil {
				return nil, WhoAmIOutput{}, err
			}
			output.APITransactionID = apiTransactionID
		}
		return &mcpsdk.CallToolResult{}, output, nil
	})
	return mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server { return server }, &mcpsdk.StreamableHTTPOptions{Stateless: true, PropagateRequestCancellation: true})
}

func signedToolMatches(ctx context.Context, target, tool string) bool {
	route, ok := middleware.VerifiedSignedRoute(ctx)
	return ok && route.Target == target && route.Tool == tool
}

func callDemoAPIStrict(ctx context.Context, client *http.Client, endpoint *url.URL, maximumTokenBytes int, expectedTransactionID string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", errors.New("create strict downstream API request")
	}
	if err := PropagateVerifiedTxnToken(ctx, request, maximumTokenBytes); err != nil {
		return "", errors.New("strict downstream API request denied")
	}
	response, err := client.Do(request)
	if err != nil {
		return "", errors.New("strict downstream API request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("strict downstream API rejected request: status=%d", response.StatusCode)
	}
	var payload struct {
		TransactionID string `json:"transaction_id"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, (1<<20)+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || decoder.Decode(&struct{}{}) != io.EOF || payload.TransactionID == "" || payload.TransactionID != expectedTransactionID {
		return "", errors.New("strict downstream API returned invalid correlation data")
	}
	return payload.TransactionID, nil
}

func callDemoAPI(ctx context.Context, client *http.Client, endpoint *url.URL, token, expectedTransactionID string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", errors.New("create downstream API request")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		return "", errors.New("downstream API request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("downstream API rejected request: status=%d", response.StatusCode)
	}
	var payload struct {
		TransactionID string `json:"transaction_id"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload); err != nil || payload.TransactionID == "" {
		return "", errors.New("downstream API returned invalid correlation data")
	}
	if payload.TransactionID != expectedTransactionID {
		return "", errors.New("downstream API transaction correlation mismatch")
	}
	return payload.TransactionID, nil
}
