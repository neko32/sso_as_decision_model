# API

Base URL: `http://127.0.0.1:8080` by default (`BIND_ADDR` / `PUBLIC_BASE_URL`).

## POST /access/v1/evaluation

OpenID AuthZEN Access Evaluation.

### Request

```json
{
  "subject":  { "type": "user", "id": "alice@example.com",
                "properties": { "roles": ["hr"], "account_status": "active" } },
  "resource": { "type": "app", "id": "payroll" },
  "action":   { "name": "read" },
  "context": {
    "time": "2026-10-30T10:00:00+09:00",
    "device":   { "managed": true, "mdm": "Intune", "disk_encrypted": true, "os": "macOS 15.4", "last_patch_days": 3 },
    "location": { "country": "JP", "city": "Tokyo", "network": "corporate" },
    "history":  { "recent_logins": [ { "time": "2026-10-29T09:12:00+09:00", "country": "JP", "city": "Tokyo" } ] },
    "signals":  { "failed_attempts_24h": 0 }
  }
}
```

| Field | Rules |
|---|---|
| `subject.id` | 1–256 chars, `[A-Za-z0-9-_.:@+]` |
| `subject.properties.roles` | lowercase `[a-z0-9-_:]`, ≤ 64 chars each; default `[]` |
| `subject.properties.account_status` | `active` (default) \| `suspended` \| `disabled` |
| `resource.id` | same as `subject.id` |
| `action.name` | same as roles |
| `context.time` | RFC 3339 with offset (used for business hours); default: now (UTC) |
| `context.*` (other) | free-form; passed to Jev as-is |

### Response `200` (illustrative values)

```json
{
  "decision": false,
  "context": {
    "outcome": "step_up",
    "reason_admin": "device judged 'byod' (confidence 0.91); resource requires a managed device",
    "model": "jev-1.14.0",
    "trace": [
      { "factor": "identity", "source": "rule",  "effect": "allow",   "detail": "account is active" },
      { "factor": "policy",   "source": "rule",  "effect": "allow",   "detail": "policy permits 'read' on 'payroll'" },
      { "factor": "role",     "source": "rule",  "effect": "allow",   "detail": "role 'hr' is authorised" },
      { "factor": "time",     "source": "rule",  "effect": "allow",   "detail": "13:00 is within allowed hours 07-22" },
      { "factor": "device",   "source": "model", "effect": "step_up", "detail": "device judged 'byod' (confidence 0.91); resource requires a managed device" },
      { "factor": "location", "source": "model", "effect": "allow",   "detail": "P(implausible location) = 0.03 (step-up at 0.60)" },
      { "factor": "time",     "source": "model", "effect": "allow",   "detail": "P(unusual login time) = 0.21 (step-up at 0.70)" },
      { "factor": "risk",     "source": "model", "effect": "allow",   "detail": "expected risk 0.40 of 3 (confidence 0.90; step-up at 1.00, deny at 2.00)" }
    ]
  }
}
```

- `decision` is `true` only for `allow`. For `step_up`, the caller should run MFA and re-evaluate.
- `context.outcome`: `allow` | `step_up` | `deny`.
- `context.model` is omitted when the model was not consulted (gate deny or fail-closed).
- `trace[].source`: `rule` (Rust), `model` (Jev or mock), `system` (fail-closed).

### Errors

| Status | When | Body |
|---|---|---|
| 400 | domain validation failed | `{"error": "subject.properties.roles contains invalid characters"}` |
| 415 | missing `content-type: application/json` | text |
| 422 | JSON shape mismatch (missing fields) | text |

Jev failures do **not** surface as errors: they produce `200` with `outcome: "deny"` (fail-closed).

## GET /.well-known/authzen-configuration

```json
{ "policy_decision_point": "http://127.0.0.1:8080",
  "access_evaluation_endpoint": "http://127.0.0.1:8080/access/v1/evaluation" }
```

## GET /healthz

`200 ok`

## Configuration

| Variable | Default | |
|---|---|---|
| `SIGNAL_MODE` | `jev` | `jev` or `mock` (offline heuristics) |
| `API_KEY_JEV` | – | required in `jev` mode |
| `JEV_MODEL` | `jev-1.14.0` | |
| `JEV_BASE_URL` | `https://api.typesafe.ai` | |
| `JEV_TIMEOUT_MS` | `5000` | |
| `BIND_ADDR` | `127.0.0.1:8080` | |
| `PUBLIC_BASE_URL` | `http://{BIND_ADDR}` | used in discovery |
| `POLICY_PATH` | `policy.yaml` | |
| `RUST_LOG` | `info` | |
