# Explainable AI SOC Assistant

An evidence-first research platform for network intrusion detection, explainable machine learning, and SOC investigation workflows.

> **Current status — Milestone 4:** validated ingestion and deterministic feature engineering; reproducible Logistic Regression, Random Forest, and XGBoost experiments; plus evidence-linked alert generation, transparent multi-factor risk scoring, triage workflow, and alert investigation. Synthetic experiments are explicitly labeled and are not evidence of real-world performance.

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
- No fabricated experiment metrics or threat-intelligence claims

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

## Quick start

```bash
cp .env.example .env
docker compose up --build
```

Open the UI at `http://localhost:5173` and the API documentation at `http://localhost:8000/docs`.

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

## Evidence labels

- **Synthetic demo data:** illustrative events designed only to exercise the interface.
- **Demo rule evidence:** transparent deterministic conditions, not ML inference.
- **Experiment results:** absent until a real dataset has been trained and evaluated.
- **MITRE ATT&CK mappings:** not emitted in Milestone 1; later mappings must include explicit supporting evidence.

## Roadmap

1. Repository foundation and dashboard shell (complete)
2. CSV ingestion, validation, and feature processing (complete)
3. Logistic Regression, Random Forest, and XGBoost experiment pipeline (complete)
4. Zeek parser and dataset-specific mapping profiles
5. Alert engine, documented risk score, and investigation workflow
6. SHAP global/local explanations and deterministic language templates
7. Evidence-backed ATT&CK context and transparent incident correlation
8. Research views, confusion matrix, error analysis, and dataset card
9. Optional grounded assistant, analyst feedback, and model monitoring

See [docs/research-roadmap.md](docs/research-roadmap.md) for the full plan.

## Limitations and responsible use

This is a defensive research and educational platform, not a replacement for professional security monitoring. Synthetic demonstrations do not establish real-world accuracy. Model outputs must be validated against representative datasets, and analysts must retain access to the original evidence. Never treat a probability, explanation, or ATT&CK hypothesis as proof of compromise.

## License

MIT — see [LICENSE](LICENSE).
