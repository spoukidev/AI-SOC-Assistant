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
- Detection rules stored in the database with explicit logic, bounded risk points, versioned edits, and links to the alerts they raised
- Incidents that group alerts, with status workflow, severity, time window, and link/unlink endpoints
- Bearer-token (JWT) authentication on every data endpoint; only `/health` and the login endpoint are open
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

## Authentication

Every `/api/*` endpoint except `POST /api/auth/login` requires `Authorization: Bearer <token>`. `/health` stays open for container health checks. The UI shows a sign-in screen and keeps the token in `sessionStorage`.

There is one admin account, configured with environment variables:

| Variable | Required | Purpose |
|---|---|---|
| `AUTH_SECRET_KEY` | Yes, outside local demos | HS256 signing key, at least 32 characters. Generate one with `python -c "import secrets; print(secrets.token_urlsafe(48))"`. If it is unset, a random key is generated at startup and tokens stop working after a restart. |
| `ADMIN_PASSWORD_HASH` | Yes, outside local demos | PBKDF2-SHA256 hash of the admin password. Generate it with `python -m app.auth hash-password` from `backend/`, or `docker compose run --rm backend python -m app.auth hash-password`. |
| `ADMIN_PASSWORD` | No | Plain-text alternative for local development. It is hashed in memory at startup. Prefer `ADMIN_PASSWORD_HASH`. |
| `ADMIN_USERNAME` | No | Defaults to `admin`. |
| `ACCESS_TOKEN_TTL_MINUTES` | No | Token lifetime. Defaults to 60, capped at 1440. |

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
5. SHAP global/local explanations, stored detection rules, analyst-managed incidents, and API authentication (complete)
6. Evidence-backed ATT&CK context and automatic, transparent incident correlation (planned)
7. Research views: confusion matrix and error analysis linked to explanations (planned)
8. Optional grounded assistant, analyst feedback, and model monitoring (planned)

Not yet implemented and not scheduled: a Zeek `conn.log` parser with dataset-specific mapping profiles, and a live rule engine that evaluates detection rules against imported events. Today the demo rule runs only when demo data is seeded.

See [docs/research-roadmap.md](docs/research-roadmap.md) for the full plan.

## Limitations and responsible use

This is a defensive research and educational platform, not a replacement for professional security monitoring. Synthetic demonstrations do not establish real-world accuracy. Model outputs must be validated against representative datasets, and analysts must retain access to the original evidence. Never treat a probability, explanation, or ATT&CK hypothesis as proof of compromise.

## License

MIT — see [LICENSE](LICENSE).
