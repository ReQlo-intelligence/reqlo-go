# ReQlo Go SDK

Server-side client for [ReQlo](https://reqlo.io), authorization for AI agents. Go 1.21+, standard library only.
Keep your project API key on your server.

```bash
go get github.com/ReQlo-intelligence/reqlo-go
```

```go
client, err := reqlo.New(os.Getenv("REQLO_API_KEY"))
if err != nil {
	log.Fatal(err)
}

_, err = client.Enforce(ctx, reqlo.AuthorizeRequest{
	Agent:    reqlo.Agent{ID: "agt_7Hq2mK9xR4vTq8Lp"},
	Subject:  &reqlo.Subject{ID: session.UserID, Kind: "user"}, // from your verified session
	Action:   "documents.read",
	Resource: reqlo.Resource{Type: "document", ID: doc.ID, Attributes: map[string]any{"owner_id": doc.OwnerID}},
	Context:  map[string]any{"document_classification": doc.Classification},
})
var denied *reqlo.DeniedError
if errors.As(err, &denied) {
	return fmt.Errorf("not allowed: %s", denied.Decision.ReasonCode)
}
if err != nil {
	return err // timeout, network or HTTP error: the action does not run
}
// Allowed: run the action.
```

- `Authorize` returns the decision; act only when `Decision == reqlo.DecisionAllow`.
- `Enforce` returns an error unless the decision is allow (`*reqlo.DeniedError` for deny or approval required).
- `client.Approvals.List`, `Retrieve`; `client.Delegations.Create`, `List`, `Retrieve`, `Revoke`.
- `reqlo.VerifyWebhook` and `reqlo.ConstructEvent` check webhook signatures.

Options: `reqlo.WithTimeout`, `reqlo.WithMaxRetries`, `reqlo.WithBaseURL`, `reqlo.WithHTTPClient`. Retries `429` and
`5xx` twice with backoff (3-second timeout). Timeouts and network errors are never retried and never mean allow.
Documentation: <https://reqlo-web.vercel.app/docs/sdks/go>
