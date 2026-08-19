# Explainable AI SOC Assistant

An evidence-first research platform for network intrusion detection, explainable machine learning, and SOC investigation workflows.

> **Current status — Milestone 1:** runnable application foundation, PostgreSQL persistence, synthetic demo events, dashboard API, and SOC dashboard shell. Detection scores shown in this milestone are deterministic demo labels—not trained-model results.

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

## Milestone 1 features

- FastAPI service with health, dashboard, event, alert, and incident endpoints
- PostgreSQL through SQLAlchemy, with automatic local schema initialization
- Clearly labeled synthetic demo dataset seeded on first startup
- React, TypeScript, Vite, Tailwind CSS, Recharts, and TanStack Query
- Responsive, original dark SOC interface with restrained severity semantics
- Docker Compose startup for frontend, backend, and database
- No fabricated experiment metrics or threat-intelligence claims

## Quick start

```bash
cp .env.example .env
docker compose up --build
```

Open the UI at `http://localhost:5173` and the API documentation at `http://localhost:8000/docs`.

## Local development

Backend (Python 3.11+):

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
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

1. Repository foundation and dashboard shell (current)
2. CSV/Zeek ingestion, validation, and feature processing
3. Logistic Regression, Random Forest, and XGBoost experiment pipeline
4. Alert engine, documented risk score, and investigation workflow
5. SHAP global/local explanations and deterministic language templates
6. Evidence-backed ATT&CK context and transparent incident correlation
7. Research views, confusion matrix, error analysis, and dataset card
8. Optional grounded assistant, analyst feedback, and model monitoring

See [docs/research-roadmap.md](docs/research-roadmap.md) for the full plan.

## Limitations and responsible use

This is a defensive research and educational platform, not a replacement for professional security monitoring. Synthetic demonstrations do not establish real-world accuracy. Model outputs must be validated against representative datasets, and analysts must retain access to the original evidence. Never treat a probability, explanation, or ATT&CK hypothesis as proof of compromise.

## License

MIT — see [LICENSE](LICENSE).
