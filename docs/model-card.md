# Model Card

## Status

Milestone 3 added Logistic Regression, Random Forest, and XGBoost artifacts trained from user-supplied labeled flow CSV files. Milestone 5 adds SHAP explanations for all three model families. No pretrained production model is included. This document defines the model scope, evaluation gates, security assumptions, and reporting requirements that must be satisfied before a trained detector is presented as a research result.

## Intended purpose

Models classify validated network-flow features for **defensive cybersecurity research** and **SOC analyst decision support**. The model is intended to help prioritize suspicious network events; it is not intended to make autonomous containment, blocking, disciplinary, or legal decisions.

## Inputs and output

Models consume the versioned `flow-v1` feature schema. Raw IP addresses are excluded. The binary output is benign (`0`) or malicious (`1`) plus the positive-class probability. Probability is not severity.

## Metrics

Metrics are stored only after a completed stratified experiment and include accuracy, precision, recall, F1, ROC-AUC, PR-AUC, TP, TN, FP, FN, and error rates. The repository does not claim a fixed performance value. Synthetic demonstration metrics are not real-world results.

## Baseline families

The comparison includes simple and stronger supervised baselines so that model complexity is justified by measured gains rather than assumed superiority.

Implemented baseline families:

- Logistic Regression
- Random Forest
- XGBoost

Other models may be added later, but they should be evaluated under the same preprocessing, split, and reporting protocol.

## Intended users

The intended users are:

- cybersecurity students and researchers,
- SOC analysts evaluating model-assisted triage,
- reviewers reproducing the project experiments,
- and developers testing explainable intrusion-detection workflows.

The model is not designed for unsupervised production deployment without environment-specific validation.

## Out-of-scope use

The model should not be used as the sole basis for:

- automatically blocking hosts or accounts,
- attributing attacks to specific people or organizations,
- claiming zero-day detection,
- inferring intent from a single network event,
- or replacing analyst investigation.

A high prediction probability must not be treated as equivalent to high incident severity.

## Input data

The planned input is a validated tabular representation of network-flow or connection-level features derived from an explicitly documented dataset.

Before training, each feature must be classified as one of the following:

- **predictive feature** — intentionally supplied to the model,
- **metadata** — stored for traceability but excluded from training,
- **label** — ground-truth target used only for supervised learning/evaluation,
- **identifier** — such as raw IP addresses or row IDs, excluded unless a research justification is documented.

Raw identifiers should not become predictive features by default because they may create dataset-specific leakage and weak generalization.

The exact schema, source, license, class mapping, known collection biases, and preprocessing decisions belong in `dataset-card.md` and the experiment configuration.

## Preprocessing requirements

Training and inference should use the same saved preprocessing pipeline to reduce training-serving skew.

The pipeline should record, as applicable:

1. schema validation,
2. missing-value handling,
3. feature engineering,
4. categorical encoding,
5. scaling or normalization,
6. feature ordering,
7. and the fitted preprocessing artifact version.

Any preprocessing step learned from data must be fitted on the training partition only.

## Output

A prediction result should keep separate fields for:

- predicted class,
- model probability or confidence,
- model version,
- preprocessing version,
- experiment ID,
- and, when supported, local explanation data.

Operational risk severity, rule evidence, ATT&CK context, and analyst verdict are separate SOC concepts and should not be silently derived from the classifier probability.

## Training protocol

A reproducible training run should record at minimum:

- dataset name and version,
- feature schema version,
- label mapping,
- split strategy,
- random seed,
- model type,
- hyperparameters,
- preprocessing configuration,
- software/library versions when relevant,
- training timestamp,
- and artifact hashes or version identifiers.

The final test set must remain isolated from model selection and hyperparameter tuning.

If the dataset is temporal or contains strongly related records, the split strategy must account for leakage risks instead of relying automatically on a random row split.

## Evaluation requirements

No experimental metric should be reported until it has been produced by a completed, reproducible experiment.

The planned evaluation should report, when applicable:

- Precision
- Recall
- F1-score
- ROC-AUC
- PR-AUC
- confusion matrix
- False Positive Rate
- False Negative Rate
- training time
- inference latency
- class-wise performance

For imbalanced intrusion-detection data, accuracy alone is insufficient. PR-AUC, recall, false-positive behavior, and class-wise results should be emphasized.

## Error analysis

Aggregate metrics are not enough. False positives and false negatives should be retained as inspectable research cases with:

- expected label,
- predicted label,
- confidence,
- relevant feature values,
- explanation output when available,
- model version,
- and experiment ID.

The project should explicitly investigate whether errors cluster around specific classes, traffic types, feature ranges, or collection conditions.

## Explainability

All three model families are explained with SHAP (Milestone 5):

| Model | Explainer | Output units |
|---|---|---|
| Logistic Regression | `shap.LinearExplainer` (interventional) | log-odds of malicious |
| Random Forest | `shap.TreeExplainer` (interventional) | probability of malicious |
| XGBoost | `shap.TreeExplainer` (interventional) | probability of malicious |

The reference distribution is a reproducible sample of up to 100 engineered training rows, saved in the artifact at training time. It contains no raw identifiers. One-hot columns are summed back to their `flow-v1` feature. Artifacts trained before Milestone 5 have no background sample and report explanations as unavailable until retrained. Global importance is the mean absolute SHAP value over the background sample.

Each local explanation returned by the API preserves:

- the feature value,
- contribution direction,
- contribution magnitude,
- predicted class,
- and model version.

An LLM or other text generator may summarize verified explanation data for readability, but generated prose must not introduce new evidence or unsupported attack claims.

Explanation quality must be evaluated separately from prediction quality. A correct prediction can still have an unstable or misleading explanation.

### Explanation stability (measured)

`GET /api/models/{id}/explanation` returns a `stability` block, and `ml/shap_stability.py` repeats the check across training seeds. The explainer is rebuilt on 5 random halves of the reference sample. We report the overlap (Jaccard) of the global top-5 features and of each explained row's top-3 features with the full-sample explanation, plus the Spearman rank correlation of the global ranking. Verdict: `stable` when both overlaps are ≥ 0.8, `moderately stable` when both are ≥ 0.6, otherwise `unstable`.

Results on the synthetic labeled demo dataset, 5 training seeds per model (`python ../ml/shap_stability.py --seeds 5 --label-noise <p>`):

| Label noise | Model | Global top-5 Jaccard (mean / min) | Local top-3 Jaccard (mean) | Rank Spearman (mean) | Verdict |
|---|---|---|---|---|---|
| 0% | Logistic Regression | 1.000 / 1.000 | 0.928 | — | stable |
| 0% | Random Forest | 1.000 / 1.000 | 0.988 | — | stable |
| 0% | XGBoost | 1.000 / 1.000 | 1.000 | — | stable |
| 10% | Logistic Regression | 0.933 / 0.800 | 0.926 | 0.993 | stable |
| 10% | Random Forest | 1.000 / 1.000 | 0.886 | 0.993 | stable |
| 10% | XGBoost | 0.947 / 0.867 | 0.938 | 0.996 | stable |
| 25% | Logistic Regression | 0.960 / 0.800 | 0.906 | 0.994 | stable |
| 25% | Random Forest | 0.947 / 0.867 | 0.893 | 0.990 | stable |
| 25% | XGBoost | 0.933 / 0.800 | 0.886 | 0.994 | stable |

How to read these numbers:

- They are an optimistic upper bound. The synthetic data is almost perfectly separable, and without label noise XGBoost relies almost entirely on `duration`, which makes the ranking trivially stable. Label noise was added to make the check less trivial; it is still not real traffic.
- They measure sensitivity to the reference sample only. They say nothing about how explanations change when the model is retrained on new data or when an input is slightly perturbed. Those checks belong to the adversarial-robustness work in Milestone 7.
- Features with near-zero attribution are ignored when picking the top features, so ties between unused features do not inflate the overlap.
- Re-run the check on any real dataset before relying on the explanations, and treat a `moderately stable` or `unstable` verdict as a reason to look at the raw evidence rather than the top features.

## Robustness and security considerations

The detector should be evaluated under an explicit defensive threat model before any robustness claim is made.

Relevant risks include:

- adversarial feature manipulation,
- training-data poisoning,
- label noise,
- dataset leakage,
- distribution shift,
- class imbalance,
- explanation manipulation or instability,
- stale preprocessing artifacts,
- and model-version confusion.

Adversarial experiments should identify which features are realistically mutable by an attacker and which represent environmental facts that should not be arbitrarily perturbed.

## Generalization and drift

Performance on a single benchmark does not establish deployment readiness.

Future evaluation should consider:

- temporal holdouts,
- cross-dataset testing,
- feature-distribution shift,
- confidence-distribution shift,
- class-prevalence changes,
- and degradation over time.

If performance drops under distribution shift, that result should be reported directly rather than hidden by aggregate in-distribution metrics.

## Known limitations

At the current milestone:

- no pretrained model artifact is included (users train their own from labeled CSV data),
- no benchmark metrics are claimed,
- synthetic UI demonstrations do not establish model performance,
- dataset-specific biases have not yet been quantified,
- adversarial robustness has not yet been measured,
- explanation stability has not yet been measured (SHAP values depend on the stored background sample),
- and production deployment suitability has not been established.

These limitations are deliberate documentation boundaries, not missing results to be filled with estimates.

## Deployment gate

A model should not be described as research-ready until the repository contains:

- a documented dataset version,
- a reproducible preprocessing pipeline,
- a reproducible training configuration,
- an isolated test evaluation,
- confusion-matrix and class-wise metrics,
- error analysis,
- model and preprocessing version tracking,
- and a limitations section tied to measured evidence.

Production deployment would require additional environment-specific validation, monitoring, governance, access control, incident-response integration, and human oversight beyond this research gate.

## Reporting principles

Every future model release should distinguish clearly between:

- **measured findings**,
- **hypotheses**,
- **planned experiments**,
- and **demonstration-only behavior**.

No model result, robustness claim, or detection capability should be added to this card unless the supporting experiment can be reproduced from repository artifacts.