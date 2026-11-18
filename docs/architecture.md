# Architecture

The React client, FastAPI service, and PostgreSQL database are separated by explicit APIs. The API owns evidence serialization and distinguishes raw network events, deterministic feature vectors, import batches, rule-derived alerts, and incidents.

Milestone 2 adds a parser boundary between uploaded CSV data and canonical events. Uploads are size/type checked, decoded as UTF-8, mapped to canonical fields, validated row by row, and normalized before persistence. Deterministic `flow-v1` features are stored in a linked table while the original row remains available in `raw_event`. This keeps identifiers available for investigation without using raw IP addresses as predictive features.

Trained pipelines persist preprocessing and the classifier together in one artifact to avoid training-serving skew.

## Milestone 5

- **Authentication:** a FastAPI dependency on the API router requires a valid HS256 bearer token for every `/api/*` route except `POST /api/auth/login`. `/health` stays open. Credentials come from environment variables (see the README).
- **Explainability:** `app/ml/explain.py` builds a SHAP explainer from the artifact's pipeline and stored background sample, caches it per artifact, and never raises into request handlers. Failures are returned as `unavailable` or `error` states.
- **Detection rules:** stored in `detection_rules`. Alerts reference their rule (`alerts.rule_id`) and incident (`alerts.incident_id`).
- **Schema upgrades:** `database.ensure_schema()` adds the new nullable columns to databases created by earlier milestones. There is no Alembic migration history yet.
