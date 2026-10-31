# Design: SSO as a Decision Model

## Idea

An SSO login is, at its core, a decision:

```
f(Identity, Device, Location, Risk, Role, Policy, Time) -> Allow | StepUp | Deny
```

This POC implements that function as a **Policy Decision Point (PDP)** exposed via the
[OpenID AuthZEN](https://openid.net/wg/authzen/) Access Evaluation API, and splits the
seven inputs by *how* they should be decided:

| Factor   | Decided by | Why |
|----------|-----------|-----|
| Identity | Rust rule | Account status is a fact, not a judgement |
| Policy   | Rust rule | Which resource/action exists is configuration (`policy.yaml`) |
| Role     | Rust rule | RBAC must be exact and auditable |
| Time     | Rust rule + Jev | Business hours are a rule; "unusual for *this* user" is a judgement |
| Device   | Jev (`choice`) | Posture data is messy and heterogeneous |
| Location | Jev (`noul`) | Impossible travel / never-seen country needs context |
| Risk     | Jev (`score`) | Holistic view across every signal |

Jev (TypeSafe System One) is a decision model: it receives a `state` and typed questions and
returns **probabilities**, not prose. That makes its output directly usable by code and by thresholds.

## Pipeline

1. **Validate** – the AuthZEN request is converted into newtypes (`SubjectId`, `RoleName`,
   `ActionName`, `ResourceId`, `AccountStatus`, RFC 3339 time). Invalid input → `400`.
2. **Deterministic gate** (`core::engine::gate`) – Identity → Policy (resource + action) → Role →
   Hours. The first failure returns **Deny** and the model is **not called** (cheap, fast,
   hard rules stay hard).
3. **Contextual signals** (`core::signals::SignalProvider`) – one batched Jev call with four
   questions: `device_trust` (choice), `location_anomaly` (noul), `time_anomaly` (noul), `risk` (score 0–3).
4. **Combine** (`core::combiner::combine`) – thresholds from `policy.yaml` map each signal to an
   effect. The final outcome is the strictest effect (`Allow < StepUp < Deny`).
5. **Trace** – every factor contributes `{factor, source, effect, detail}` so each decision is explainable.

### Combination rules (defaults)

| Signal | Deny | Step-up |
|--------|------|---------|
| device_trust | `compromised` | `unknown`, or `byod` on a `require_managed_device` resource |
| location_anomaly | – | ≥ 0.6 |
| time_anomaly | – | ≥ 0.7 |
| risk (0–3) | ≥ 2.0 | ≥ 1.0 |

## Module layout

```
app/src/
├── main.rs            # env/.env → Config → build_app → axum::serve
├── lib.rs             # build_app wiring
├── config.rs          # SIGNAL_MODE, API_KEY_JEV, JEV_* …
├── api/
│   ├── authzen.rs     # AuthZEN DTOs ↔ domain
│   ├── jev.rs         # JevClient (reqwest) + typed questions + answer parsing
│   └── server.rs      # Axum router
└── core/
    ├── domain.rs      # newtypes, Outcome, DeviceTrust
    ├── policy.rs      # policy.yaml loading/validation
    ├── signals.rs     # SignalProvider trait, RuleBased mock, Static stub
    ├── combiner.rs    # signals → effects, TraceEntry
    └── engine.rs      # gate + orchestration + fail-closed
```

External dependencies sit behind the `SignalProvider` trait:

| Implementation | Used by |
|---|---|
| `JevClient` | production / live tests (`SIGNAL_MODE=jev`) |
| `RuleBasedSignalProvider` | offline mode for CI and Playwright (`SIGNAL_MODE=mock`) |
| `StaticSignalProvider` | unit tests (fixed result or error) |

## Security decisions (とちまる)

- **Fail-closed**: any Jev failure (timeout, transport error, 401/429/529/5xx, a missing or
  out-of-range answer) → `Deny` with a `source: system` trace entry.
- **Pinned model**: `jev-1.14.0`, not `jev-latest`, so decisions don't change silently when a new release ships.
- **Data minimisation**: the subject id (e.g. email) is never sent to Jev; only roles, resource,
  action, time and the context the client supplied.
- **Secret hygiene**: `API_KEY_JEV` is wrapped in `ApiKey`, whose `Debug` prints `ApiKey(****)`;
  reqwest errors are stripped of URLs before being surfaced.
- **Default deny**: unknown resources have no policy → Deny.
- **Supply chain**: `cargo audit` is clean. `serde_yaml_ng` was swapped for the pure-Rust
  `serde-saphyr` to drop the unmaintained `unsafe-libyaml` (RUSTSEC-2024-0449).
- POC limitations: no authentication on the PDP endpoint itself (deploy behind mTLS or a gateway),
  the subject id appears in info logs, and there is no retry/backoff on 429/529 (it fails closed instead).

## Testing (ぐんまちゃん)

| Layer | Tooling | Jev |
|---|---|---|
| Unit (29) | `cargo test` | `StaticSignalProvider` |
| Integration (5) | Axum `oneshot` + `wiremock` | HTTP stub: allow/step-up/deny, 401/429/500/529, garbage, unreachable, `expect(0)` for gate denies, state minimisation |
| Live (1, `--ignored`) | real API | safe vs hijacked login |
| E2E (8) | Playwright `APIRequestContext` | `mock` in CI, `jev` locally |

Line coverage: **95.5 %** (`docs/coverage/html/index.html`).
