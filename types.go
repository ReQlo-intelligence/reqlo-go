package reqlo

// Agent is the registered agent making the request. Your server chooses it, never the model.
type Agent struct {
	ID string `json:"id"`
}

// Subject is the person or entity the agent acts for, from your verified session.
type Subject struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

// Resource is what the action targets. Attributes come from your own database.
type Resource struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// AuthorizeRequest asks whether an agent may perform an action. Attribute values are strings, numbers,
// booleans or []string, and must match the schemas registered for the action and resource type.
type AuthorizeRequest struct {
	Agent        Agent          `json:"agent"`
	Subject      *Subject       `json:"subject,omitempty"`
	Action       string         `json:"action"`
	Resource     Resource       `json:"resource"`
	Context      map[string]any `json:"context,omitempty"`
	DelegationID string         `json:"delegation_id,omitempty"`
	ApprovalID   string         `json:"approval_id,omitempty"`
}

// Decision outcomes. Only DecisionAllow permits the action.
const (
	DecisionAllow            = "allow"
	DecisionDeny             = "deny"
	DecisionApprovalRequired = "approval_required"
)

// PendingApproval is set on a Decision when its outcome is DecisionApprovalRequired.
type PendingApproval struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	ExpiresAt string `json:"expires_at"`
}

// Decision is ReQlo's answer. Act only when Decision.Decision == DecisionAllow.
type Decision struct {
	ID            string           `json:"id"`
	Object        string           `json:"object"`
	Decision      string           `json:"decision"`
	Allowed       bool             `json:"allowed"`
	ReasonCode    string           `json:"reason_code"`
	MatchedRules  []string         `json:"matched_rules"`
	PolicyVersion *string          `json:"policy_version"`
	Approval      *PendingApproval `json:"approval"`
	Environment   string           `json:"environment"`
	Livemode      bool             `json:"livemode"`
	CreatedAt     string           `json:"created_at"`
	RequestID     string           `json:"request_id"`
}

// ApprovalSummary describes what is being approved.
type ApprovalSummary struct {
	AgentID   string `json:"agent_id,omitempty"`
	SubjectID string `json:"subject_id,omitempty"`
	Action    string `json:"action,omitempty"`
	Resource  string `json:"resource,omitempty"`
}

// Approval is a human sign-off on one exact request.
type Approval struct {
	ID            string          `json:"id"`
	Object        string          `json:"object"`
	Status        string          `json:"status"`
	DecisionID    *string         `json:"decision_id"`
	RequestDigest string          `json:"request_digest"`
	Summary       ApprovalSummary `json:"summary"`
	ChannelID     *string         `json:"channel_id"`
	ExpiresAt     string          `json:"expires_at"`
	ResolvedBy    *string         `json:"resolved_by"`
	ResolvedAt    *string         `json:"resolved_at"`
	Note          *string         `json:"note"`
	CreatedAt     string          `json:"created_at"`
}

// ApprovalList is the environment's approvals, newest first.
type ApprovalList struct {
	Data          []Approval `json:"data"`
	EnvironmentID string     `json:"environment_id"`
}

// Delegation is a person's grant letting one agent perform actions for them until it expires or is revoked.
type Delegation struct {
	ID           string   `json:"id"`
	Object       string   `json:"object"`
	AgentID      string   `json:"agent_id"`
	Subject      Subject  `json:"subject"`
	Actions      []string `json:"actions"`
	Verification struct {
		Method string `json:"method"`
	} `json:"verification"`
	Status    string  `json:"status"`
	ExpiresAt string  `json:"expires_at"`
	CreatedAt string  `json:"created_at"`
	RevokedAt *string `json:"revoked_at"`
}

// DelegationCreateParams records a grant. Take Subject from your verified session, after the person consents.
type DelegationCreateParams struct {
	AgentID   string   `json:"agent_id"`
	Subject   Subject  `json:"subject"`
	Actions   []string `json:"actions"`
	ExpiresAt string   `json:"expires_at"`
}

// DelegationListParams filters List. Both are optional.
type DelegationListParams struct {
	AgentID   string
	SubjectID string
}
