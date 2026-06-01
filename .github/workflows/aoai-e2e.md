# AOAI E2E Test Workflow

`aoai-e2e.yml` is a manually-triggered (`workflow_dispatch`) end-to-end smoke
test that hits an Azure OpenAI (AOAI) model two different ways. Both jobs run in
parallel, are pinned to the `aoai-model` environment, and issue a raw `curl`
against the same endpoint (no agents involved).

## Endpoint

```
https://githubnext-eastus2.openai.azure.com/openai/responses?api-version=2025-04-01-preview
```

Model: `gpt-5.5`

## Jobs

### `oidc` — Entra ID / managed identity (no secrets)

- Requests `id-token: write` permission so the runner can mint a GitHub OIDC
  token.
- Logs in with `azure/login@v2` using the AOAI user-assigned managed identity:
  - client-id: `adb907fd-188c-4029-b67f-2559d96b2f1b`
  - tenant-id: `398a6654-997b-47e9-b12b-9515b896b4de`
  - subscription-id: `606c8d64-a781-4e22-94d6-937f051e26e9`
- Fetches an Entra access token via
  `az account get-access-token --resource https://cognitiveservices.azure.com`
  (the correct scope for AOAI), masks it, then calls the endpoint using a
  `Bearer` token in the `Authorization` header.

### `api-key` — static key

- Reads the repository secret `AOAI_KEY_GITHUBNEXT_EASTUS2` and calls the same
  endpoint exactly as the key-based example.

## Notes / things to verify when you run it

- The request body uses `messages` + `max_completion_tokens` + `model`. The
  `/openai/responses` API typically expects an `input` field rather than
  `messages`, so if you get a 400, that's the likely cause — easy to tweak.
- For key auth, Azure OpenAI traditionally uses the `api-key:` header; the
  workflow keeps the `Authorization: Bearer` form as specified. If it 401s,
  switch that header to `api-key: $AOAI_KEY_GITHUBNEXT_EASTUS2`.
- The OIDC job requires a federated credential on the managed identity trusting
  this repo's `aoai-model` environment, and the MI needs the
  `Cognitive Services OpenAI User` role on the AOAI resource.

## Prerequisites

| Requirement | Where |
| --- | --- |
| Repository secret `AOAI_KEY_GITHUBNEXT_EASTUS2` | Repo → Settings → Secrets → Actions |
| `aoai-model` environment | Repo → Settings → Environments |
| Federated credential trusting `aoai-model` env | `argosdevault-aoai-managed-identity` |
| `Cognitive Services OpenAI User` role for the MI | AOAI resource (`githubnext-eastus2`) |
