# Architecture

The React client, FastAPI service, and PostgreSQL database are separated by explicit APIs. The API owns evidence serialization and distinguishes raw network events, deterministic feature vectors, import batches, rule-derived alerts, and incidents.

Milestone 2 adds a parser boundary between uploaded CSV data and canonical events. Uploads are size/type checked, decoded as UTF-8, mapped to canonical fields, validated row by row, and normalized before persistence. Deterministic `flow-v1` features are stored in a linked table while the original row remains available in `raw_event`. This keeps identifiers available for investigation without using raw IP addresses as predictive features.

Trained pipelines persist preprocessing and the classifier together in one artifact to avoid training-serving skew.

## Milestone 5

- **Authentication:** a FastAPI dependency on the API router requires a valid HS256 bearer token for every `/api/*` route except `POST /api/auth/login`. `/health` stays open. Credentials come from environment variables (see the README).
- **Explainability:** `app/ml/explain.py` builds a SHAP explainer from the artifact's pipeline and stored background sample, caches it per artifact, and never raises into request handlers. Failures are returned as `unavailable` or `error` states.
- **Detection rules:** stored in `detection_rules`. Alerts reference their rule (`alerts.rule_id`) and incident (`alerts.incident_id`).
- **Session cookies and CSRF:** login sets an HttpOnly, SameSite=Strict cookie scoped to `/api`. The JWT carries a random `csrf` claim; cookie-authenticated writes must echo it in `X-CSRF-Token` and come from an allowed `Origin`. Bearer-header requests (scripts) skip the CSRF check. A middleware adds security headers to every response.
- **Live rule engine:** `app/security/rule_engine.py` evaluates enabled rules with stored `conditions` (an allowlisted field/operator DSL) on every CSV import and on `POST /api/detection-rules/evaluate`. Alerts record `rule_version` and a unique `dedup_key`, so repeated imports do not create duplicate alerts.
- **Correlation:** `app/security/correlation.py` attaches new alerts to an open incident keyed by `src:<ip>` when they fall within the configured window, creating the incident once `CORRELATION_MIN_ALERTS` is reached. It refreshes first/last seen and only ever raises severity. Alerts with `manual_correlation` set (any manual link or unlink) are skipped.
- **SHAP stability:** `explain.stability()` rebuilds the explainer on random halves of the reference sample and reports top-k overlap and rank correlation. The result is cached per artifact and returned with the global explanation.
- **Schema upgrades:** `database.ensure_schema()` adds the new nullable columns to databases created by earlier milestones. There is no Alembic migration history yet.
