# Explainable AI SOC Assistant

[![CI](https://github.com/spoukidev/AI-SOC-Assistant/actions/workflows/ci.yml/badge.svg)](https://github.com/spoukidev/AI-SOC-Assistant/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An evidence-first research platform for network intrusion detection, explainable machine learning, and SOC investigation workflows.

> **Current status — Milestone 5:** validated ingestion and deterministic feature engineering; reproducible Logistic Regression, Random Forest, and XGBoost experiments; evidence-linked alerts with transparent risk scoring and triage; **SHAP global and per-alert explanations**, stored **detection rules**, analyst-managed **incidents**, and **authenticated API access**. Synthetic experiments are explicitly labeled and are not evidence of real-world performance.

## Research objective

This project studies whether explainable machine learning can make network intrusion detection alerts more useful and interpretable to SOC analysts. Detection will remain independent of any LLM; future language-model integration is optional and grounded only in stored evidence.

## Architecture

```text
Network data -> ingestion -> feature processing -> ML + rules
                                                  |
                                      alerts -> explanations
                                                  |
                                  incidents -> SOC dashboard
                                                  |
                                  optional grounded assistant
```

## Implemented features

- FastAPI service with health, dashboard, event, alert, and incident endpoints
- PostgreSQL through SQLAlchemy, with automatic local schema initialization
- Clearly labeled synthetic demo dataset seeded on first startup
- React, TypeScript, Vite, Tailwind CSS, Recharts, and TanStack Query
- Responsive, original dark SOC interface with restrained severity semantics
- Docker Compose startup for frontend, backend, and database
- Secure CSV uploads with 5 MB and 10,000-row limits
- Canonical field mapping with common network-flow column aliases
- Per-row validation for timestamps, IP addresses, ports, counts, and duration
- Deterministic `flow-v1` feature vectors stored separately from raw evidence
- Import provenance, acceptance/rejection counts, and traceable row errors
- Network Events workspace with upload, import history, and feature readiness
- Shared saved preprocessing/classifier pipelines for training and inference
- Logistic Regression, Random Forest, and XGBoost through a common detector interface
- Stratified train/validation/test splits with fixed random seeds
- Accuracy, precision, recall, F1, ROC-AUC, PR-AUC, confusion counts, and error rates
- Immutable experiment/model metadata, dataset SHA-256, timing, and joblib artifacts
- Experiment, model-comparison, dataset, and prediction research pages
- SHAP explanations computed from the trained model: per-alert local explanations (top features with signed contributions) and global mean |SHAP| importance per model version
- SHAP stability check: the global explanation reports how much the top features change when the explainer is rebuilt on different halves of the reference sample
- Detection rules stored in the database with explicit logic, bounded risk points, versioned edits, and links to the alerts they raised
- Live rule engine: enabled rules with machine-readable conditions run on every CSV import. Each alert records the rule and rule version that raised it, and re-importing the same flows never creates duplicate alerts
- Incidents that group alerts, with status workflow, severity, time window, and link/unlink endpoints
- Automatic correlation of new alerts into incidents by source IP within a configurable time window, with first/last seen and severity kept up to date. Manual link/unlink still works and always wins
- Authentication on every data endpoint (only `/health`, login and logout are open): HttpOnly, SameSite=Strict session cookie with CSRF protection for the UI, and bearer tokens for scripts
- Security headers on every API response (CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`) and on the nginx-served UI
- No fabricated experiment metrics, model scores, or threat-intelligence claims

## CSV format

Required columns:

```text
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,duration,packets,bytes
```

Optional columns include `tcp_flags`, `src_bytes`, `dst_bytes`, `src_packets`, and `dst_packets`. Timestamps use ISO 8601. A safe example is available at `ml/datasets/synthetic-demo-flows.csv`.

The ingestion pipeline calculates duration, total packets/bytes, bytes per packet, packets/bytes per second, directional ratios, port categories, protocol, and TCP-flag presence. Raw IP addresses are preserved as evidence but deliberately excluded from predictive feature vectors.

## Model experiments

Generate the explicitly labeled synthetic demonstration dataset and train a baseline:

```powershell
cd backend
.\.venv\Scripts\python.exe ..\ml\generate_demo_dataset.py
.\.venv\Scripts\python.exe ..\ml\train.py ..\ml\datasets\synthetic-labeled-demo.csv --model logistic_regression
```

Available `--model` values are `logistic_regression`, `random_forest`, and `xgboost`. The `.joblib` artifact contains preprocessing and the classifier; the adjacent metadata JSON records dataset hash, features, seed, split, parameters, timing, and measured metrics.

Metrics from `synthetic-labeled-demo.csv` demonstrate pipeline execution only. They must not be cited as network-intrusion detection performance.

## Explainability (SHAP)

Training stores a reproducible sample of up to 100 engineered training rows (no IP addresses) inside the model artifact as the SHAP reference distribution.

- **Logistic Regression** uses `shap.LinearExplainer`; values are in **log-odds** of the malicious class.
- **Random Forest and XGBoost** use interventional `shap.TreeExplainer`; values are in **probability** of the malicious class.
- One-hot encoded columns are summed back to their original `flow-v1` feature, so analysts see 12 understandable features.
- `GET /api/alerts/{id}` returns the local explanation for ML alerts: base value, model output, the top 8 contributions, and the sum of the rest. Base value plus contributions equals the model output, and the tests check this.
- `GET /api/models/{id}/explanation` returns global importance over the stored background sample.
- Rule-only alerts, including all seeded demo alerts, return `status: "not_applicable"` instead of an invented explanation. Models trained before Milestone 5 return `status: "unavailable"` until they are retrained.

SHAP values explain the model's output relative to its training baseline. They are not proof of malicious activity and not a causal statement about the network flow.

### Stability check

`GET /api/models/{id}/explanation` also returns a `stability` block. The explainer is rebuilt on 5 random halves of the stored reference sample (seeded, so the result is reproducible), and the report gives:

- `global_top_k_jaccard`: mean overlap of the global top-5 features between resamples and the full sample.
- `local_top3_jaccard`: mean overlap of each explained row's top-3 features.
- `global_rank_spearman`: rank correlation of the full global importance ranking.
- `verdict`: `stable` when both overlaps are at least 0.8, `moderately stable` when both are at least 0.6, otherwise `unstable`.

To measure it across seeds, label noise and models:

```bash
cd backend
python ../ml/shap_stability.py --seeds 5 --label-noise 0.1
```

This measures sensitivity to the reference sample only. It does not measure how explanations change when the model is retrained or when an input is slightly changed. See the [model card](docs/model-card.md) for the measured numbers and their caveats.

## Live rule engine

Enabled rules that have `conditions` run on every CSV import. Each event raises at most one alert: the matching rule with the highest risk points wins, and other matching rules are listed in the alert evidence. The alert stores `rule_id` and `rule_version`, uses the event timestamp, and gets the same documented risk score as before (rule points, plus 10 asset points for remote-access or database ports, plus repeated-activity points).

Each alert has a dedup key (SHA-256 of rule key, UTC timestamp and flow fields) with a unique index, so importing the same CSV twice or running the rules again creates no duplicate alerts. The import response reports `alerts_created`, `duplicate_alerts_skipped` and `incidents_updated`.

Built-in live rules (thresholds are illustrative, not tuned on a real network):

| Key | Logic | Points |
|---|---|---|
| `syn-probe-sensitive-service-v1` | TCP, SYN without ACK, sensitive port, ≤ 6 packets | 20 |
| `small-packet-burst-v1` | ≥ 500 packets/s, ≤ 80 bytes/packet, ≥ 50 packets | 15 |
| `cleartext-remote-admin-v1` | TCP to port 21 or 23, ≥ 10 packets | 10 |

The seeded demo rule has no conditions and stays catalog-only. Custom rules:

```bash
curl -X POST http://localhost:8000/api/detection-rules -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{
  "key": "rdp-from-outside-v1", "name": "Inbound RDP", "description": "Any flow to RDP", "risk_points": 12,
  "conditions": [{"field": "dst_port", "op": "eq", "value": 3389}, {"field": "protocol", "op": "eq", "value": "TCP"}]}'
```

Conditions are ANDed, at most 10 per rule. Fields: `protocol`, `src_port`, `dst_port`, `duration`, `packets`, `bytes`, `tcp_flags`, and the `flow-v1` features (`bytes_per_packet`, `packets_per_second`, `bytes_per_second`, `src_dst_byte_ratio`, `src_dst_packet_ratio`, `src_port_category`, `dst_port_category`, `has_tcp_flags`). Operators: `eq`, `ne`, `in`, `not_in`, `contains`, `not_contains` (for `tcp_flags` these compare whole flag tokens), `gt`, `gte`, `lt`, `lte`. Changing conditions with `PATCH /api/detection-rules/{id}` bumps the version; existing alerts keep their original version and evidence. `POST /api/detection-rules/evaluate` runs the enabled rules over stored events that have no alert yet (the UI has a "Run on stored events" button).

## Incident correlation

New rule and ML alerts are grouped by source IP. When at least `CORRELATION_MIN_ALERTS` alerts from the same source fall within `CORRELATION_WINDOW_MINUTES` of each other, they are attached to an open incident with key `src:<ip>`, or a new incident "Correlated activity from <ip>" is created. The incident's first/last seen are refreshed, and its severity is raised to the highest alert severity (never lowered automatically).

- Alerts you link or unlink by hand are marked as manually correlated and are never moved again automatically.
- Resolved and closed incidents are not reopened; a new incident is created instead.
- A shared source IP is a triage hint, not proof that the alerts belong to one attack. NAT, proxies and shared hosts will group unrelated activity.

## Authentication

Every `/api/*` endpoint except `POST /api/auth/login` and `POST /api/auth/logout` requires a session. `/health` stays open for container health checks.

- **Browser (UI):** login sets the `soc_xai_session` cookie: `HttpOnly`, `SameSite=Strict`, `Path=/api`, and `Secure` unless `AUTH_COOKIE_SECURE=false`. JavaScript never sees the token. The token carries a random CSRF value, which the UI reads from `GET /api/auth/me` and keeps in memory only. Every cookie-authenticated `POST`, `PATCH`, `PUT` or `DELETE` must send it in `X-CSRF-Token`, and must come from an allowed origin when an `Origin` header is present; otherwise the API returns 403.
- **Scripts:** send `{"username": ..., "password": ..., "issue_bearer_token": true}` to the login endpoint and use `Authorization: Bearer <token>`. Bearer requests do not need a CSRF token, because browsers never attach that header on their own.
- `POST /api/auth/logout` clears the cookie.

Every API response sets `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` (the `/docs` and `/redoc` pages only get `frame-ancestors 'none'` so Swagger UI can load). HTTPS requests also get `Strict-Transport-Security`. The nginx config that serves the UI adds matching headers.

`BACKEND_CORS_ORIGINS` must list exact origins; `*` is rejected at startup because credentials are allowed. The UI and API must be on the same site (for example `localhost:5173` and `localhost:8000`, or the same domain) for the `SameSite=Strict` cookie to be sent.

There is one admin account, configured with environment variables:

| Variable | Required | Purpose |
|---|---|---|
| `AUTH_SECRET_KEY` | Yes, outside local demos | HS256 signing key, at least 32 characters. Generate one with `python -c "import secrets; print(secrets.token_urlsafe(48))"`. If it is unset, a random key is generated at startup and tokens stop working after a restart. |
| `ADMIN_PASSWORD_HASH` | Yes, outside local demos | PBKDF2-SHA256 hash of the admin password. Generate it with `python -m app.auth hash-password` from `backend/`, or `docker compose run --rm backend python -m app.auth hash-password`. |
| `ADMIN_PASSWORD` | No | Plain-text alternative for local development. It is hashed in memory at startup. Prefer `ADMIN_PASSWORD_HASH`. |
| `ADMIN_USERNAME` | No | Defaults to `admin`. |
| `ACCESS_TOKEN_TTL_MINUTES` | No | Token lifetime. Defaults to 60, capped at 1440. |
| `AUTH_COOKIE_SECURE` | No | Defaults to `true`. Set `false` only when the UI is served over plain HTTP on a host other than `localhost` (browsers already accept Secure cookies on `http://localhost`). |

Detection and correlation settings:

| Variable | Default | Purpose |
|---|---|---|
| `RULE_ENGINE_ENABLED` | `true` | Run enabled live rules on CSV import and allow `POST /api/detection-rules/evaluate`. |
| `AUTO_CORRELATION_ENABLED` | `true` | Group new alerts into incidents by source IP. |
| `CORRELATION_WINDOW_MINUTES` | `60` | Maximum gap between alerts from one source that are grouped together (1 to 10080). |
| `CORRELATION_MIN_ALERTS` | `2` | Alerts needed before a new incident is created (1 to 100). |

No working default password is shipped. If neither `ADMIN_PASSWORD_HASH` nor `ADMIN_PASSWORD` is set, the backend generates a random one-time password and prints it once as a startup warning in the backend log. Five failed logins from one client within five minutes return HTTP 429.

## Quick start

```bash
cp .env.example .env
# Set AUTH_SECRET_KEY and ADMIN_PASSWORD_HASH in .env (see Authentication above)
docker compose up --build
```

Open the UI at `http://localhost:5173` and the API documentation at `http://localhost:8000/docs`. If you did not set an admin password, find the generated one in `docker compose logs backend`.

## Local development

Backend (Python 3.11+). Use a virtual environment so the project's pinned
packages do not replace packages used by other Python projects:

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

If PowerShell blocks activation, the virtual environment can be used without
activating it:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Frontend (Node 20+):

```bash
cd frontend
npm install
npm run dev
```

Without `DATABASE_URL`, the backend uses a local SQLite file for convenient development. Docker uses PostgreSQL.

Existing databases are upgraded on startup: new tables are created and the Milestone 5 columns (`alerts.rule_id`, `alerts.incident_id`, `incidents.synthetic`) are added. Demo alerts seeded by older versions lose their made-up probabilities and are linked to the demo rule and incidents.

Tests:

```bash
cd backend && pytest -q
cd frontend && npm test && npm run build
```

## Evidence labels

- **Synthetic demo data:** illustrative events designed only to exercise the interface.
- **Demo rule evidence:** transparent deterministic conditions, not ML inference. Seeded alerts have no model probability; their risk comes only from rule, asset-context, and repeated-activity points.
- **Experiment results:** absent until a real dataset has been trained and evaluated.
- **SHAP explanations:** only for alerts raised by a trained model's prediction.
- **MITRE ATT&CK mappings:** not emitted yet; later mappings must include explicit supporting evidence.

## Roadmap

1. Repository foundation and dashboard shell (complete)
2. CSV ingestion, validation, and feature processing (complete)
3. Logistic Regression, Random Forest, and XGBoost experiment pipeline (complete)
4. Alert engine, documented risk score, and investigation workflow (complete)
5. SHAP global/local explanations with a stability check, a live versioned rule engine, incidents with automatic source-IP correlation, and cookie/CSRF-protected authentication (complete)
6. Evidence-backed ATT&CK context and richer correlation (destination, technique, time pattern) (planned)
7. Research views: confusion matrix and error analysis linked to explanations (planned)
8. Optional grounded assistant, analyst feedback, and model monitoring (planned)

Not yet implemented and not scheduled: a Zeek `conn.log` parser with dataset-specific mapping profiles.

Known limitations of Milestone 5:

- One admin account and no roles.
- Sessions are stateless JWTs. Logout clears the cookie, but a stolen token stays valid until it expires; there is no server-side revocation.
- The login rate limit is kept in memory per process; it resets on restart and is not shared between workers.
- Rule thresholds are illustrative and have not been tuned on real traffic.
- Correlation uses the source IP only.
- Re-importing a CSV stores the events again; only alerts are deduplicated.
- Schema changes are additive columns applied at startup; there are no Alembic migrations yet.

See [docs/research-roadmap.md](docs/research-roadmap.md) for the full plan.

## Limitations and responsible use

This is a defensive research and educational platform, not a replacement for professional security monitoring. Synthetic demonstrations do not establish real-world accuracy. Model outputs must be validated against representative datasets, and analysts must retain access to the original evidence. Never treat a probability, explanation, or ATT&CK hypothesis as proof of compromise.

## License

MIT — see [LICENSE](LICENSE).
