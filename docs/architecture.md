# Architecture

Milestone 1 separates the React client, FastAPI service, and PostgreSQL database. The API owns evidence serialization and clearly distinguishes raw network events, rule-derived alerts, and incidents. Future ML pipelines will persist preprocessing and model artifacts together to avoid training-serving skew.
