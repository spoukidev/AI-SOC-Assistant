# Research Roadmap

1. Baseline application and synthetic demonstration — implemented
2. Validated ingestion and feature pipeline — implemented
3. Reproducible model comparison — implemented
4. Alert engine, transparent risk scoring, triage dashboard, and alert investigation — implemented
5. SHAP explainability (global and per-alert), stored detection rules, analyst-managed incidents, and API authentication — implemented
6. Evidence-backed ATT&CK context and automatic correlation
7. Adversarial robustness
8. Cross-dataset generalization
9. Analyst feedback study

## Milestone 5 notes

- Explanations use the training background sample stored in each artifact (up to 100 rows of engineered features). Logistic regression explanations are in log-odds; tree-model explanations are in probability.
- Explanation stability (for example, sensitivity to the background sample or to small feature perturbations) has not been measured yet. That belongs with the adversarial-robustness work in milestone 7.
- Incident correlation is manual. Automatic correlation belongs to milestone 6.
- Not yet scheduled: a Zeek `conn.log` parser and a live rule engine for imported events.
