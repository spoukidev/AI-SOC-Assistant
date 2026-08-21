# Architecture

The React client, FastAPI service, and PostgreSQL database are separated by explicit APIs. The API owns evidence serialization and distinguishes raw network events, deterministic feature vectors, import batches, rule-derived alerts, and incidents.

Milestone 2 adds a parser boundary between uploaded CSV data and canonical events. Uploads are size/type checked, decoded as UTF-8, mapped to canonical fields, validated row by row, and normalized before persistence. Deterministic `flow-v1` features are stored in a linked table while the original row remains available in `raw_event`. This keeps identifiers available for investigation without using raw IP addresses as predictive features.

Future trained pipelines will persist preprocessing and model artifacts together to avoid training-serving skew.
