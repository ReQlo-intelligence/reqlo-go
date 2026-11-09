package reqlo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strconv"
	"time"
)

// WebhookTolerance is how far a webhook timestamp may be from now.
const WebhookTolerance = 300 * time.Second

var (
	signaturePattern = regexp.MustCompile(`^t=(\d{1,12}),v1=([a-f0-9]{64})$`)
	secretPattern    = regexp.MustCompile(`^whsec_[a-f0-9]{64}$`)
)

// Event is a webhook event. An event never authorizes an action: fetch the approval and redeem the
// original request before running anything.
type Event struct {
	ID            string `json:"id"`
	Object        string `json:"object"`
	Type          string `json:"type"`
	EnvironmentID string `json:"environment_id"`
	CreatedAt     string `json:"created_at"`
	Data          struct {
		Object struct {
			ID        string `json:"id"`
			Object    string `json:"object"`
			Status    string `json:"status"`
			ExpiresAt string `json:"expires_at"`
		} `json:"object"`
	} `json:"data"`
}

// VerifyWebhook reports whether header (the Reqlo-Signature header) signs the exact raw body with secret,
// with a timestamp within WebhookTolerance of now.
func VerifyWebhook(payload []byte, header, secret string, now time.Time) bool {
	match := signaturePattern.FindStringSubmatch(header)
	if match == nil || !secretPattern.MatchString(secret) {
		return false
	}
	timestamp, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil {
		return false
	}
	if diff := now.Unix() - timestamp; diff > int64(WebhookTolerance.Seconds()) || diff < -int64(WebhookTolerance.Seconds()) {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(match[1] + "."))
	mac.Write(payload)
	expected, _ := hex.DecodeString(match[2])
	return hmac.Equal(mac.Sum(nil), expected)
}

// ConstructEvent verifies the signature and parses the event. It returns ErrInvalidSignature if it isn't valid.
func ConstructEvent(payload []byte, header, secret string, now time.Time) (*Event, error) {
	if !VerifyWebhook(payload, header, secret, now) {
		return nil, ErrInvalidSignature
	}
	var event Event
	if json.Unmarshal(payload, &event) != nil || event.Object != "event" || event.Type == "" {
		return nil, ErrInvalidSignature
	}
	return &event, nil
}
