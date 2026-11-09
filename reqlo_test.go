package reqlo

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const now = "2026-11-09T10:42:07.123Z"

var approvalJSON = map[string]any{"id": "APR_7Hq2mK9xR4vTq8Lp", "object": "approval", "status": "pending", "decision_id": nil,
	"request_digest": "sha256:" + strings.Repeat("a", 64), "summary": map[string]any{"agent_id": "agt_x", "action": "documents.read"},
	"channel_id": nil, "expires_at": now, "resolved_by": nil, "resolved_at": nil, "note": nil, "created_at": now}
var delegationJSON = map[string]any{"id": "DEL_5Hq2mK9xR4vTq8Lp", "object": "delegation", "agent_id": "agt_x", "subject": map[string]any{"id": "usr_94", "kind": "user"},
	"actions": []string{"calendar.schedule"}, "verification": map[string]any{"method": "server_session"}, "status": "active", "expires_at": now, "created_at": now, "revoked_at": nil}

func decisionJSON(kind string) map[string]any {
	d := map[string]any{"id": "dec_1", "object": "decision", "decision": kind, "allowed": kind == "allow", "reason_code": "policy_denied",
		"matched_rules": []string{}, "policy_version": "2026-11-09.1", "approval": nil, "environment": "sandbox", "livemode": false, "created_at": now, "request_id": "r1"}
	if kind == "allow" {
		d["reason_code"] = "policy_allowed"
	}
	if kind == "approval_required" {
		d["reason_code"] = "approval_required"
		d["approval"] = map[string]any{"id": "APR_7Hq2mK9xR4vTq8Lp", "status": "pending", "expires_at": now}
	}
	return d
}

type reply struct {
	status  int
	body    any
	headers map[string]string
	sleep   time.Duration
}

type fake struct {
	mu       sync.Mutex
	replies  []reply
	requests []*http.Request
	bodies   []map[string]any
}

func (f *fake) serve(t *testing.T) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		f.mu.Lock()
		f.requests = append(f.requests, r)
		f.bodies = append(f.bodies, body)
		next := reply{status: 500, body: map[string]any{}}
		if len(f.replies) > 0 {
			next, f.replies = f.replies[0], f.replies[1:]
		}
		f.mu.Unlock()
		time.Sleep(next.sleep)
		for k, v := range next.headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(next.status)
		if s, ok := next.body.(string); ok {
			_, _ = w.Write([]byte(s))
			return
		}
		_ = json.NewEncoder(w).Encode(next.body)
	}))
	t.Cleanup(server.Close)
	client, err := New("rq_test_secret", WithBaseURL(server.URL+"/v1"), WithTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return client
}

var request = AuthorizeRequest{Agent: Agent{ID: "agt_x"}, Action: "documents.read", Resource: Resource{Type: "document", ID: "doc_1"}}

func TestAuthorizeSendsTheRequest(t *testing.T) {
	f := &fake{replies: []reply{{status: 200, body: decisionJSON("allow")}}}
	c := f.serve(t)
	req := request
	req.Subject = &Subject{ID: "usr_1", Kind: "user"}
	req.Context = map[string]any{"level": 2}
	d, err := c.Authorize(context.Background(), req)
	if err != nil || d.Decision != DecisionAllow {
		t.Fatalf("got %v %v", d, err)
	}
	r := f.requests[0]
	if r.Method != "POST" || r.URL.Path != "/v1/authorize" || r.Header.Get("Authorization") != "Bearer rq_test_secret" {
		t.Fatalf("bad request %s %s", r.Method, r.URL.Path)
	}
	if f.bodies[0]["subject"].(map[string]any)["kind"] != "user" || f.bodies[0]["context"].(map[string]any)["level"] != float64(2) {
		t.Fatalf("bad body %v", f.bodies[0])
	}
	if _, present := f.bodies[0]["delegation_id"]; present {
		t.Fatal("empty optional fields must be omitted")
	}
}

func TestEnforce(t *testing.T) {
	f := &fake{replies: []reply{{status: 200, body: decisionJSON("allow")}, {status: 200, body: decisionJSON("deny")}, {status: 200, body: decisionJSON("approval_required")}}}
	c := f.serve(t)
	if _, err := c.Enforce(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	var denied *DeniedError
	if _, err := c.Enforce(context.Background(), request); !errors.As(err, &denied) || denied.Decision.ReasonCode != "policy_denied" {
		t.Fatalf("want denied, got %v", err)
	}
	if _, err := c.Enforce(context.Background(), request); !errors.As(err, &denied) || denied.Decision.Approval.ID != "APR_7Hq2mK9xR4vTq8Lp" {
		t.Fatalf("want approval required, got %v", err)
	}
}

func TestMalformedResponsesAreErrors(t *testing.T) {
	bad := []any{map[string]any{"decision": "allow"}, "not json", func() any { d := decisionJSON("allow"); d["allowed"] = false; return d }(),
		func() any { d := decisionJSON("deny"); d["allowed"] = true; return d }(), func() any { d := decisionJSON("allow"); d["decision"] = "maybe"; return d }()}
	for i, body := range bad {
		f := &fake{replies: []reply{{status: 200, body: body}}}
		if _, err := f.serve(t).Enforce(context.Background(), request); !errors.Is(err, ErrResponse) {
			t.Fatalf("case %d: want ErrResponse, got %v", i, err)
		}
	}
}

func TestRetries5xxThenReturnsAPIError(t *testing.T) {
	r := reply{status: 503, body: map[string]any{"error": map[string]any{"code": "service_unavailable", "request_id": "r9"}}, headers: map[string]string{"Retry-After": "0"}}
	f := &fake{replies: []reply{r, r, r}}
	_, err := f.serve(t).Authorize(context.Background(), request)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 503 || apiErr.Code != "service_unavailable" || apiErr.RequestID != "r9" || len(f.requests) != 3 {
		t.Fatalf("got %v after %d requests", err, len(f.requests))
	}
}

func TestClientErrorsAreNotRetriedAndUnknownCodesHidden(t *testing.T) {
	f := &fake{replies: []reply{{status: 422, body: map[string]any{"error": map[string]any{"code": "something_secret", "message": "secret"}}}}}
	_, err := f.serve(t).Authorize(context.Background(), request)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "" || strings.Contains(err.Error(), "secret") || len(f.requests) != 1 {
		t.Fatalf("got %v", err)
	}
}

func TestTimeoutsAndNetworkErrors(t *testing.T) {
	f := &fake{replies: []reply{{status: 200, body: decisionJSON("allow"), sleep: 300 * time.Millisecond}}}
	c := f.serve(t)
	c.timeout = 50 * time.Millisecond
	if _, err := c.Enforce(context.Background(), request); !errors.Is(err, ErrTimeout) {
		t.Fatalf("want timeout, got %v", err)
	}
	offline, _ := New("rq_test_x", WithBaseURL("http://127.0.0.1:9/v1"), WithMaxRetries(0))
	if _, err := offline.Enforce(context.Background(), request); !errors.Is(err, ErrNetwork) {
		t.Fatalf("want network error, got %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := offline.Enforce(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("want cancelled, got %v", err)
	}
}

func TestDelegationCreateIsNeverRetried(t *testing.T) {
	f := &fake{replies: []reply{{status: 503, body: map[string]any{}, headers: map[string]string{"Retry-After": "0"}}}}
	_, err := f.serve(t).Delegations.Create(context.Background(), DelegationCreateParams{AgentID: "agt_x", Subject: Subject{ID: "u", Kind: "user"}, Actions: []string{"a.b"}, ExpiresAt: now})
	if err == nil || len(f.requests) != 1 {
		t.Fatalf("got %v after %d requests", err, len(f.requests))
	}
}

func TestApprovalsAndDelegations(t *testing.T) {
	revoked := map[string]any{}
	for k, v := range delegationJSON {
		revoked[k] = v
	}
	revoked["status"], revoked["revoked_at"] = "revoked", now
	f := &fake{replies: []reply{{status: 200, body: map[string]any{"data": []any{approvalJSON}, "environment_id": "env"}}, {status: 200, body: approvalJSON},
		{status: 201, body: delegationJSON}, {status: 200, body: map[string]any{"data": []any{delegationJSON}}}, {status: 200, body: delegationJSON}, {status: 200, body: revoked}}}
	c := f.serve(t)
	ctx := context.Background()
	if list, err := c.Approvals.List(ctx, "pending"); err != nil || list.Data[0].ID != "APR_7Hq2mK9xR4vTq8Lp" {
		t.Fatal(err)
	}
	if a, err := c.Approvals.Retrieve(ctx, "APR_7Hq2mK9xR4vTq8Lp"); err != nil || a.Summary.Action != "documents.read" {
		t.Fatal(err)
	}
	if d, err := c.Delegations.Create(ctx, DelegationCreateParams{AgentID: "agt_x", Subject: Subject{ID: "usr_94", Kind: "user"}, Actions: []string{"calendar.schedule"}, ExpiresAt: now}); err != nil || d.Status != "active" {
		t.Fatal(err)
	}
	if list, err := c.Delegations.List(ctx, DelegationListParams{SubjectID: "usr_94"}); err != nil || len(list) != 1 {
		t.Fatal(err)
	}
	if _, err := c.Delegations.Retrieve(ctx, "DEL_5Hq2mK9xR4vTq8Lp"); err != nil {
		t.Fatal(err)
	}
	if d, err := c.Delegations.Revoke(ctx, "DEL_5Hq2mK9xR4vTq8Lp"); err != nil || d.Status != "revoked" {
		t.Fatal(err)
	}
	var paths []string
	for _, r := range f.requests {
		paths = append(paths, r.Method+" "+r.URL.RequestURI())
	}
	want := "GET /v1/approvals?status=pending,GET /v1/approvals/APR_7Hq2mK9xR4vTq8Lp,POST /v1/delegations,GET /v1/delegations?subject_id=usr_94,GET /v1/delegations/DEL_5Hq2mK9xR4vTq8Lp,POST /v1/delegations/DEL_5Hq2mK9xR4vTq8Lp/revoke"
	if strings.Join(paths, ",") != want {
		t.Fatalf("paths %v", paths)
	}
}

func TestConfiguration(t *testing.T) {
	cases := []func() error{
		func() error { _, err := New("sk_nope"); return err },
		func() error { _, err := New("rq_test_x", WithBaseURL("http://api.reqlo.io/v1")); return err },
		func() error { _, err := New("rq_test_x", WithBaseURL("https://api.reqlo.io/v2")); return err },
		func() error { _, err := New("rq_test_x", WithTimeout(0)); return err },
		func() error { _, err := New("rq_test_x", WithMaxRetries(9)); return err },
	}
	for i, c := range cases {
		var cfg *ConfigurationError
		if err := c(); !errors.As(err, &cfg) {
			t.Fatalf("case %d: want configuration error, got %v", i, err)
		}
	}
	c, _ := New("rq_test_secret")
	if strings.Contains(fmt.Sprintf("%v %+v", c.baseURL, c.Approvals), "rq_test_secret") {
		t.Fatal("key leaked")
	}
	if _, err := c.Approvals.Retrieve(context.Background(), "nope"); err == nil {
		t.Fatal("want error")
	}
}

func sign(secret, body string, ts int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.%s", ts, body)
	return fmt.Sprintf("t=%d,v1=%s", ts, hex.EncodeToString(mac.Sum(nil)))
}

func TestWebhooks(t *testing.T) {
	secret := "whsec_" + strings.Repeat("b", 64)
	body := `{"id":"EVT_1","object":"event","type":"approval.requested","data":{"object":{"id":"APR_7Hq2mK9xR4vTq8Lp","status":"pending"}}}`
	at := time.Unix(1_800_000_000, 0)
	if !VerifyWebhook([]byte(body), sign(secret, body, at.Unix()), secret, at) {
		t.Fatal("valid signature rejected")
	}
	for name, ok := range map[string]bool{
		"old":        VerifyWebhook([]byte(body), sign(secret, body, at.Unix()-301), secret, at),
		"tampered":   VerifyWebhook([]byte(body+" "), sign(secret, body, at.Unix()), secret, at),
		"wrong key":  VerifyWebhook([]byte(body), sign("whsec_"+strings.Repeat("c", 64), body, at.Unix()), secret, at),
		"no header":  VerifyWebhook([]byte(body), "", secret, at),
		"bad secret": VerifyWebhook([]byte(body), sign(secret, body, at.Unix()), "nope", at),
	} {
		if ok {
			t.Fatalf("%s accepted", name)
		}
	}
	event, err := ConstructEvent([]byte(body), sign(secret, body, at.Unix()), secret, at)
	if err != nil || event.Type != "approval.requested" || event.Data.Object.ID != "APR_7Hq2mK9xR4vTq8Lp" {
		t.Fatalf("got %v %v", event, err)
	}
	if _, err := ConstructEvent([]byte(body), "t=1,v1="+strings.Repeat("0", 64), secret, at); !errors.Is(err, ErrInvalidSignature) {
		t.Fatal("want ErrInvalidSignature")
	}
}
