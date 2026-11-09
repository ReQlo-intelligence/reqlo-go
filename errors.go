package reqlo

import (
	"errors"
	"fmt"
)

// Every error means the protected action must stay stopped. None of them is ever an allow.
var (
	// ErrTimeout: the request timed out. Not retried, because it may have reached ReQlo.
	ErrTimeout = errors.New("reqlo: the request timed out; the protected action must remain stopped")
	// ErrNetwork: the request could not be completed.
	ErrNetwork = errors.New("reqlo: the request could not be completed; the protected action must remain stopped")
	// ErrResponse: ReQlo returned a response that isn't valid.
	ErrResponse = errors.New("reqlo: invalid response; the protected action must remain stopped")
	// ErrInvalidSignature: a webhook signature is missing, invalid or too old.
	ErrInvalidSignature = errors.New("reqlo: webhook signature is missing, invalid or too old")
)

// ConfigurationError reports invalid options or arguments.
type ConfigurationError struct{ Message string }

func (e *ConfigurationError) Error() string { return "reqlo: " + e.Message }

// APIError is an HTTP error from ReQlo. Code is a stable error code when ReQlo sent a known one.
type APIError struct {
	Status    int
	Code      string
	RequestID string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("reqlo: ReQlo returned HTTP %d; the protected action must remain stopped", e.Status)
}

// DeniedError is returned by Enforce for deny or approval_required. Decision holds the full decision.
type DeniedError struct{ Decision *Decision }

func (e *DeniedError) Error() string {
	if e.Decision != nil && e.Decision.Decision == DecisionApprovalRequired {
		return "reqlo: this action requires human approval"
	}
	return "reqlo: this action was denied"
}
