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
- Explanation stability is measured for sensitivity to the background sample (see the model card). Sensitivity to small feature perturbations and to retraining is still open and belongs with the adversarial-robustness work in milestone 7.
- New alerts are correlated into incidents by source IP within a configurable window. Richer correlation (destination, technique, time pattern) belongs to milestone 6.
- Enabled rules with machine-readable conditions run on every import. Rule thresholds are illustrative and need tuning on a real dataset.
- Not yet scheduled: a Zeek `conn.log` parser.
