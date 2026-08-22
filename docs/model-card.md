# Model Card

## Status

No trained model artifact is included in the current milestone. This document defines the intended model scope, evaluation gates, security assumptions, and reporting requirements that must be satisfied before a trained detector is presented as a research result.

## Intended purpose

Future models will classify validated network-flow features for **defensive cybersecurity research** and **SOC analyst decision support**. The model is intended to help prioritize suspicious network events; it is not intended to make autonomous containment, blocking, disciplinary, or legal decisions.

The planned comparison includes simple and stronger supervised baselines so that model complexity is justified by measured gains rather than assumed superiority.

Candidate baseline families include:

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

For supported models, SHAP may be used to provide global and local feature-attribution evidence.

A local explanation should preserve:

- the feature value,
- contribution direction,
- contribution magnitude,
- predicted class,
- and model version.

An LLM or other text generator may summarize verified explanation data for readability, but generated prose must not introduce new evidence or unsupported attack claims.

Explanation quality must be evaluated separately from prediction quality. A correct prediction can still have an unstable or misleading explanation.

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

- no trained model artifact is included,
- no benchmark metrics are claimed,
- synthetic UI demonstrations do not establish model performance,
- dataset-specific biases have not yet been quantified,
- adversarial robustness has not yet been measured,
- explanation stability has not yet been measured,
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