// Package reqlo is the server-side Go client for ReQlo, authorization for AI agents.
//
// Keep your project API key on your server. Run Enforce right before the action and act only when it returns
// without an error: a deny, an approval requirement, a timeout and any HTTP error all return an error.
package reqlo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Version of this SDK.
const Version = "0.1.0"

const defaultBaseURL = "https://api.reqlo.io/v1"

var (
	keyPattern        = regexp.MustCompile(`^rq_\S+$`)
	approvalIDPattern = regexp.MustCompile(`^APR_[A-Za-z0-9]{16}$`)
	delegationPattern = regexp.MustCompile(`^DEL_[A-Za-z0-9]{16}$`)
	requestIDPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	statuses          = map[string]bool{"pending": true, "approved": true, "rejected": true, "expired": true, "consumed": true}
	// Only these codes are surfaced, so response bodies never reach your logs.
	knownCodes = map[string]bool{"method_not_allowed": true, "parameter_invalid": true, "attribute_invalid": true, "action_unknown": true,
		"request_too_large": true, "invalid_json": true, "invalid_request": true, "api_key_required": true, "api_key_invalid": true,
		"api_key_revoked": true, "scope_missing": true, "authentication_required": true, "user_session_required": true,
		"resource_missing": true, "rate_limited": true, "internal_error": true, "service_unavailable": true}
)

// Client calls the ReQlo API. Create one with New and reuse it; it is safe for concurrent use.
type Client struct {
	apiKey      string
	baseURL     string
	timeout     time.Duration
	maxRetries  int
	httpClient  *http.Client
	Approvals   *ApprovalsService
	Delegations *DelegationsService
}

// Option configures a Client.
type Option func(*Client) error

// WithBaseURL sets the API URL. It must be HTTPS and end in /v1 (loopback HTTP is allowed for development).
func WithBaseURL(raw string) Option {
	return func(c *Client) error {
		u, err := url.Parse(raw)
		host := ""
		if err == nil {
			host = u.Hostname()
		}
		local := err == nil && u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1")
		if err != nil || (u.Scheme != "https" && !local) || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "/v1" && u.Path != "/v1/") {
			return &ConfigurationError{"base URL must be HTTPS with path /v1 and no credentials, query or fragment"}
		}
		c.baseURL = u.Scheme + "://" + u.Host + "/v1"
		return nil
	}
}

// WithTimeout sets the per-attempt timeout (default 3 seconds, at most 120).
func WithTimeout(d time.Duration) Option {
	return func(c *Client) error {
		if d <= 0 || d > 120*time.Second {
			return &ConfigurationError{"timeout must be between 0 and 120 seconds"}
		}
		c.timeout = d
		return nil
	}
}

// WithMaxRetries sets how many times 429 and 5xx responses are retried (default 2, at most 5).
func WithMaxRetries(n int) Option {
	return func(c *Client) error {
		if n < 0 || n > 5 {
			return &ConfigurationError{"max retries must be between 0 and 5"}
		}
		c.maxRetries = n
		return nil
	}
}

// WithHTTPClient uses your own *http.Client (for proxies or instrumentation). Redirects are never followed.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) error {
		if h == nil {
			return &ConfigurationError{"HTTP client must not be nil"}
		}
		copied := *h
		copied.CheckRedirect = noRedirect
		c.httpClient = &copied
		return nil
	}
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// New creates a client with your secret project API key (rq_test_...).
func New(apiKey string, options ...Option) (*Client, error) {
	if !keyPattern.MatchString(apiKey) {
		return nil, &ConfigurationError{"a secret project API key (rq_...) is required"}
	}
	c := &Client{apiKey: apiKey, baseURL: defaultBaseURL, timeout: 3 * time.Second, maxRetries: 2,
		httpClient: &http.Client{CheckRedirect: noRedirect}}
	for _, option := range options {
		if err := option(c); err != nil {
			return nil, err
		}
	}
	c.Approvals = &ApprovalsService{c}
	c.Delegations = &DelegationsService{c}
	return c, nil
}

// Authorize returns the decision. Act only when Decision == DecisionAllow.
func (c *Client) Authorize(ctx context.Context, request AuthorizeRequest) (*Decision, error) {
	var d Decision
	if err := c.do(ctx, http.MethodPost, "/authorize", request, &d, true); err != nil {
		return nil, err
	}
	if err := validDecision(&d); err != nil {
		return nil, err
	}
	return &d, nil
}

// Enforce returns the decision only on allow. Deny and approval_required return a *DeniedError; any failure
// returns another error. Put the protected action after a nil error.
func (c *Client) Enforce(ctx context.Context, request AuthorizeRequest) (*Decision, error) {
	d, err := c.Authorize(ctx, request)
	if err != nil {
		return nil, err
	}
	if d.Decision != DecisionAllow {
		return nil, &DeniedError{Decision: d}
	}
	return d, nil
}

// ApprovalsService reads approvals in the key's environment.
type ApprovalsService struct{ c *Client }

// List returns approvals, newest first. status is optional ("" for all).
func (s *ApprovalsService) List(ctx context.Context, status string) (*ApprovalList, error) {
	path := "/approvals"
	if status != "" {
		if !statuses[status] {
			return nil, &ConfigurationError{"status must be pending, approved, rejected, expired or consumed"}
		}
		path += "?status=" + status
	}
	var list ApprovalList
	if err := s.c.do(ctx, http.MethodGet, path, nil, &list, true); err != nil {
		return nil, err
	}
	if list.Data == nil || list.EnvironmentID == "" {
		return nil, ErrResponse
	}
	for i := range list.Data {
		if err := validApproval(&list.Data[i]); err != nil {
			return nil, err
		}
	}
	return &list, nil
}

// Retrieve reads one approval.
func (s *ApprovalsService) Retrieve(ctx context.Context, id string) (*Approval, error) {
	if !approvalIDPattern.MatchString(id) {
		return nil, &ConfigurationError{"use an approval ID returned by ReQlo"}
	}
	var a Approval
	if err := s.c.do(ctx, http.MethodGet, "/approvals/"+id, nil, &a, true); err != nil {
		return nil, err
	}
	return &a, validApproval(&a)
}

// DelegationsService records, reads and revokes delegations.
type DelegationsService struct{ c *Client }

// Create records a grant. It is never retried automatically: after a timeout, List to check before trying again.
func (s *DelegationsService) Create(ctx context.Context, params DelegationCreateParams) (*Delegation, error) {
	if params.AgentID == "" || params.Subject.ID == "" || params.Subject.Kind == "" || len(params.Actions) == 0 || params.ExpiresAt == "" {
		return nil, &ConfigurationError{"delegations need AgentID, Subject, Actions and ExpiresAt"}
	}
	var d Delegation
	if err := s.c.do(ctx, http.MethodPost, "/delegations", params, &d, false); err != nil {
		return nil, err
	}
	return &d, validDelegation(&d)
}

// List returns delegations, optionally for one agent or subject.
func (s *DelegationsService) List(ctx context.Context, params DelegationListParams) ([]Delegation, error) {
	query := url.Values{}
	if params.AgentID != "" {
		query.Set("agent_id", params.AgentID)
	}
	if params.SubjectID != "" {
		query.Set("subject_id", params.SubjectID)
	}
	path := "/delegations"
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	var list struct {
		Data []Delegation `json:"data"`
	}
	if err := s.c.do(ctx, http.MethodGet, path, nil, &list, true); err != nil {
		return nil, err
	}
	if list.Data == nil {
		return nil, ErrResponse
	}
	for i := range list.Data {
		if err := validDelegation(&list.Data[i]); err != nil {
			return nil, err
		}
	}
	return list.Data, nil
}

// Retrieve reads one delegation.
func (s *DelegationsService) Retrieve(ctx context.Context, id string) (*Delegation, error) {
	if !delegationPattern.MatchString(id) {
		return nil, &ConfigurationError{"use a delegation ID returned by ReQlo"}
	}
	var d Delegation
	if err := s.c.do(ctx, http.MethodGet, "/delegations/"+id, nil, &d, true); err != nil {
		return nil, err
	}
	return &d, validDelegation(&d)
}

// Revoke revokes a delegation immediately.
func (s *DelegationsService) Revoke(ctx context.Context, id string) (*Delegation, error) {
	if !delegationPattern.MatchString(id) {
		return nil, &ConfigurationError{"use a delegation ID returned by ReQlo"}
	}
	var d Delegation
	if err := s.c.do(ctx, http.MethodPost, "/delegations/"+id+"/revoke", struct{}{}, &d, true); err != nil {
		return nil, err
	}
	return &d, validDelegation(&d)
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any, retry bool) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return &ConfigurationError{"the request must be JSON serializable"}
		}
	}
	for attempt := 0; ; attempt++ {
		status, header, raw, err := c.once(ctx, method, path, payload)
		if err != nil {
			return err
		}
		if status >= 200 && status < 300 {
			if json.Unmarshal(raw, out) != nil {
				return ErrResponse
			}
			return nil
		}
		apiErr := &APIError{Status: status}
		var envelope struct {
			Error struct {
				Code      string `json:"code"`
				RequestID string `json:"request_id"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &envelope)
		if knownCodes[envelope.Error.Code] {
			apiErr.Code = envelope.Error.Code
		}
		requestID := envelope.Error.RequestID
		if requestID == "" {
			requestID = header.Get("Reqlo-Request-Id")
		}
		if requestIDPattern.MatchString(requestID) {
			apiErr.RequestID = requestID
		}
		retryable := status == 429 || (status >= 500 && status <= 599)
		if !retry || !retryable || attempt >= c.maxRetries {
			return apiErr
		}
		delay, ok := retryDelay(header.Get("Retry-After"), attempt)
		if !ok {
			return apiErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
}

func (c *Client) once(ctx context.Context, method, path string, payload []byte) (int, http.Header, []byte, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(attemptCtx, method, c.baseURL+path, reader)
	if err != nil {
		return 0, nil, nil, &ConfigurationError{"could not build the request"}
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "reqlo-go/"+Version)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, nil, classify(ctx, attemptCtx, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return 0, nil, nil, classify(ctx, attemptCtx, err)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return 0, nil, nil, ErrResponse
	}
	return resp.StatusCode, resp.Header, raw, nil
}

func classify(parent, attempt context.Context, err error) error {
	if parent.Err() != nil {
		return parent.Err()
	}
	var netErr net.Error
	if errors.Is(attempt.Err(), context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return ErrTimeout
	}
	return ErrNetwork
}

func retryDelay(header string, attempt int) (time.Duration, bool) {
	delay := time.Duration(math.Min(5000, 250*math.Pow(2, float64(attempt))*(0.75+rand.Float64()*0.5))) * time.Millisecond
	if header = strings.TrimSpace(header); header != "" {
		if seconds, err := strconv.ParseFloat(header, 64); err == nil && seconds >= 0 {
			delay = time.Duration(seconds * float64(time.Second))
		} else if at, err := http.ParseTime(header); err == nil {
			delay = time.Until(at)
			if delay < 0 {
				delay = 0
			}
		}
	}
	// Surface the error rather than wait a long, server-directed time.
	return delay, delay <= 10*time.Second
}
