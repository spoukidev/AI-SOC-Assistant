# Research Methodology

This project is designed as a reproducible cybersecurity research platform rather than a dashboard that simply displays model predictions. The methodology separates **measured evidence**, **model outputs**, **analyst decisions**, and **AI-generated interpretation** so that every conclusion can be traced back to its source.

## 1. Research Questions

The initial study focuses on the following questions:

1. How accurately can supervised machine-learning models distinguish benign and malicious network-flow behavior?
2. Which network features contribute most strongly to intrusion-detection decisions?
3. Can local SHAP explanations make alerts easier for a SOC analyst to interpret?
4. How stable are explanations across similar network events?
5. What trade-offs exist between predictive performance, inference cost, false-positive rate, and explainability?
6. How does performance change when traffic differs from the model's training distribution?

## 2. Experimental Reproducibility

Every experiment should record enough metadata to be repeated later:

- dataset name and version
- dataset source and license
- preprocessing configuration
- selected feature set
- label mapping
- train/validation/test split strategy
- random seed
- model type
- hyperparameters
- training timestamp
- software/library versions when relevant
- measured metrics

Random seeds should be fixed where possible. The final test set must remain isolated from model selection and hyperparameter tuning.

## 3. Data Preparation

The ingestion and preprocessing pipeline should be deterministic and shared between training and inference to reduce training-serving skew.

Recommended pipeline:

```text
Raw network event
      ↓
Schema validation
      ↓
Cleaning / missing-value handling
      ↓
Feature engineering
      ↓
Categorical encoding
      ↓
Scaling when required
      ↓
Saved preprocessing pipeline
      ↓
Model input
```

Raw identifiers such as IP addresses should not be used as predictive features unless their use is explicitly justified, because they can introduce dataset-specific leakage and poor generalization.

## 4. Baseline Models

The first model comparison should include at least:

- Logistic Regression — interpretable linear baseline
- Random Forest — non-linear ensemble baseline
- XGBoost — boosted-tree model

Additional detectors may be added later, but stronger models should always be compared against simple baselines.

## 5. Evaluation Metrics

Accuracy alone is insufficient for intrusion detection. Experiments should report, when applicable:

- Precision
- Recall
- F1-score
- ROC-AUC
- PR-AUC
- True Positives
- True Negatives
- False Positives
- False Negatives
- False Positive Rate
- False Negative Rate
- Training time
- Inference time

False positives are especially important because excessive alert volume can create SOC analyst fatigue.

No metric should be displayed as an experimental result until it has actually been produced by a completed experiment.

## 6. Explainability Evaluation

SHAP is used to expose feature contributions for supported models.

Two explanation levels are required:

### Global explanation

Used to study which features influence the model across the evaluated dataset.

Possible outputs include:

- global feature ranking
- SHAP summary plots
- class-specific feature influence

### Local explanation

Used to explain a single alert.

For each prediction, store:

- predicted class
- model probability/confidence
- top positive feature contributions
- top negative feature contributions
- observed feature values
- human-readable deterministic interpretation

The human-readable explanation must be derived from the actual feature values and SHAP contributions. An optional language model may rewrite verified facts for clarity but must not create new evidence.

## 7. Separating Security Concepts

The interface must distinguish the following concepts:

- **Prediction:** what the classifier predicts
- **Model confidence:** the probability or confidence score returned by the model
- **Risk severity:** an operational score that may incorporate additional context
- **Rule evidence:** deterministic security-rule matches
- **ATT&CK context:** evidence-backed mapping to possible techniques
- **Analyst verdict:** human assessment after investigation

A high model probability is not automatically equivalent to a critical security incident.

## 8. Error Analysis

False positives and false negatives should be treated as first-class research outputs.

For each error example, retain:

- original event
- expected label
- predicted label
- model confidence
- top explanatory features
- model version
- experiment ID

The research interface should make it possible to inspect these cases instead of presenting only aggregate metrics.

## 9. Generalization and Drift

A model that performs well on one dataset may fail in a different network environment. Future experiments should therefore include:

- cross-dataset evaluation
- temporal splits when appropriate
- feature-distribution comparison
- confidence-distribution monitoring
- concept-drift analysis

Performance degradation under distribution shift should be documented rather than hidden.

## 10. Adversarial Robustness

Future work will study adversarial machine learning under an explicit threat model.

Potential questions include:

- Which flow-derived features can realistically be manipulated by an attacker?
- How sensitive are predictions to controlled feature perturbations?
- Do robust feature selection or adversarial training improve resistance to evasion?

Adversarial experiments must remain defensive, reproducible, and limited to controlled datasets or authorized environments.

## 11. Analyst Feedback

The platform should collect optional analyst feedback such as:

- Was the alert correct? Yes / No / Uncertain
- Was the explanation useful? 1–5
- Analyst comment

This enables future analysis of explanation usefulness, false-positive behavior, and human trust in explainable AI.

## 12. Reporting Principles

All research reporting should follow these rules:

- never fabricate model metrics
- never claim zero-day detection without supporting evaluation
- never treat synthetic demo data as research results
- clearly document dataset and model limitations
- preserve negative results
- distinguish measured findings from hypotheses
- keep experiment configuration reproducible

The objective is a technically honest SOC research platform whose results can be inspected, repeated, and challenged.