package reqlo

import (
	"regexp"
	"time"
)

// Every response is checked, so a malformed or contradictory response is an error, never an allow.

var (
	digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	datePattern   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`)
)

func validDate(value string) bool {
	if !datePattern.MatchString(value) {
		return false
	}
	_, err := time.Parse("2006-01-02T15:04:05", value[:19])
	return err == nil
}

func validNullableDate(value *string) bool { return value == nil || validDate(*value) }

func validDecision(d *Decision) error {
	if d.ID == "" || d.Object != "decision" || d.ReasonCode == "" || d.MatchedRules == nil || d.Environment == "" || !validDate(d.CreatedAt) || d.RequestID == "" {
		return ErrResponse
	}
	switch d.Decision {
	case DecisionApprovalRequired:
		if d.Allowed || d.Approval == nil || !approvalIDPattern.MatchString(d.Approval.ID) || d.Approval.Status != "pending" || !validDate(d.Approval.ExpiresAt) {
			return ErrResponse
		}
	case DecisionAllow, DecisionDeny:
		if d.Allowed != (d.Decision == DecisionAllow) || d.Approval != nil {
			return ErrResponse
		}
	default:
		return ErrResponse
	}
	return nil
}

func validApproval(a *Approval) error {
	if !approvalIDPattern.MatchString(a.ID) || a.Object != "approval" || !statuses[a.Status] || !digestPattern.MatchString(a.RequestDigest) ||
		!validDate(a.ExpiresAt) || !validNullableDate(a.ResolvedAt) || !validDate(a.CreatedAt) {
		return ErrResponse
	}
	return nil
}

func validDelegation(d *Delegation) error {
	if !delegationPattern.MatchString(d.ID) || d.Object != "delegation" || d.AgentID == "" || d.Subject.ID == "" || d.Subject.Kind == "" ||
		len(d.Actions) == 0 || d.Verification.Method != "server_session" || !(d.Status == "active" || d.Status == "revoked" || d.Status == "expired") ||
		!validDate(d.ExpiresAt) || !validDate(d.CreatedAt) || !validNullableDate(d.RevokedAt) {
		return ErrResponse
	}
	return nil
}
