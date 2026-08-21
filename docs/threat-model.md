# Threat Model

This document defines the security assumptions, trust boundaries, adversary classes, assets, abuse cases, and planned mitigations for the Explainable AI SOC Assistant. It is intentionally conservative: controls that are not yet implemented are described as **planned**, not as existing protections.

## Scope

The project is a defensive research platform for network-event ingestion, intrusion-detection experiments, explainability, alert investigation, and future evidence-grounded AI assistance. The current implementation is an early milestone with synthetic demo events and deterministic demo labels; trained-model claims, production-grade authorization, and external threat-intelligence integrations are outside the current implementation.

The threat model covers:

- uploaded or imported network-security data;
- feature-processing and future ML inference pipelines;
- alert and incident records;
- explainability artifacts such as SHAP values;
- future RAG/LLM assistance that consumes stored evidence;
- the web/API application and database;
- model and experiment artifacts produced by future milestones.

It does not assume that an ML model, an explanation method, or an LLM is itself a security boundary.

## Security objectives

The platform should preserve four properties:

1. **Evidence integrity** — original events, labels, model outputs, and analyst actions must not be silently altered or confused with generated interpretation.
2. **Decision traceability** — an alert or incident conclusion should be traceable to source events, model/rule evidence, model version, and relevant analyst actions.
3. **Least privilege** — future users, services, models, and tools should receive only the data and actions required for their role.
4. **Research reproducibility** — datasets, preprocessing, model versions, splits, metrics, and experiment metadata should be recorded so reported results can be independently checked.

Availability is important for a SOC workflow, but this research prototype prioritizes evidence integrity and reproducibility over production-scale resilience.

## Assets

| Asset | Why it matters | Primary risk |
|---|---|---|
| Raw network events | Ground truth for investigation and experiments | Tampering, deletion, sensitive-data exposure |
| Dataset labels | Drive training and evaluation | Label poisoning and misleading metrics |
| Preprocessing pipeline | Defines model inputs | Training-serving skew, hidden leakage |
| Trained model artifacts | Determine predictions | Replacement, extraction, stale-version use |
| Experiment metadata | Supports reproducibility | Metric fabrication or configuration loss |
| Alert/incident records | Drive analyst decisions | Tampering, false correlation, alert flooding |
| SHAP/explanation data | Influences analyst trust | Misinterpretation or explanation manipulation |
| Analyst feedback/notes | May affect future evaluation | Unauthorized access or poisoning |
| Credentials/configuration | Protect infrastructure | Secret disclosure |
| Future LLM/RAG context | Shapes generated analysis | Prompt injection, data exfiltration, ungrounded claims |

## Trust boundaries

The most important boundaries are shown below.

```text
Untrusted / external data
        |
        v
+-----------------------+
| Ingestion validation  |
+-----------------------+
        |
        v
+-----------------------+       +----------------------+
| Stored source events  | ----> | Feature processing   |
+-----------------------+       +----------------------+
                                         |
                                         v
                               +----------------------+
                               | ML / rule detection  |
                               +----------------------+
                                         |
                                         v
                               +----------------------+
                               | Alerts / explanations|
                               +----------------------+
                                         |
                       +-----------------+-----------------+
                       |                                   |
                       v                                   v
             +------------------+                +-------------------+
             | Analyst workflow |                | Future AI assistant|
             +------------------+                +-------------------+
                                                         |
                                                         v
                                                Restricted local tools
```

Each arrow that crosses from user-controlled data into a processing component is a trust boundary. Retrieved text, uploaded files, model output, SHAP explanations, and generated language are all treated as **untrusted inputs to downstream decisions** unless independently validated.

## Adversaries

### External attacker

An attacker whose traffic appears in imported events may try to evade detection, trigger misleading alerts, or manipulate observable features.

Representative goals:

- evade a classifier;
- blend malicious traffic into benign distributions;
- generate alert floods to create analyst fatigue;
- cause misleading incident correlation.

### Compromised internal host

A compromised asset may look more trustworthy because it uses internal addresses or expected protocols.

Representative goals:

- abuse trust based on source location;
- perform low-and-slow reconnaissance;
- mimic common administrative traffic;
- generate plausible but malicious lateral-movement patterns.

### Malicious or careless data importer

A person with access to dataset upload/import functionality may supply malformed or adversarial data.

Representative goals:

- exploit file parsing;
- poison labels or features;
- trigger excessive resource consumption;
- introduce duplicated or leakage-prone records;
- manipulate experiment conclusions.

### Adversarial-ML attacker

An attacker may target the learning system rather than the surrounding application.

Representative goals:

- **evasion:** change mutable features to cross the model decision boundary;
- **poisoning:** influence training data or labels;
- **model extraction:** approximate model behavior through repeated queries;
- **membership/privacy inference:** infer whether sensitive examples were present in training;
- **explanation manipulation:** preserve a prediction while changing which features appear most influential;
- **distribution-shift exploitation:** operate in traffic regimes not represented during training.

### Malicious document/content author (future RAG/LLM milestone)

A future assistant may consume analyst notes, incident text, threat-intelligence records, or retrieved documents. Any such content can contain adversarial instructions.

Representative goals:

- indirect prompt injection;
- instruction-hierarchy confusion;
- exfiltration of unrelated context;
- manipulation of tool calls;
- fabricated ATT&CK mappings or conclusions;
- misleading analyst recommendations.

## Primary abuse cases

### 1. Dataset poisoning

**Scenario:** attacker-controlled or low-quality records are introduced into training data so the classifier learns misleading correlations.

**Impact:** degraded recall/precision, targeted misclassification, or apparently strong but invalid evaluation results.

**Planned mitigations:**

- record dataset provenance and checksums;
- separate raw, cleaned, train, validation, and test artifacts;
- never overwrite original imported data in place;
- detect duplicates and suspicious label distributions;
- retain split seeds and preprocessing configuration;
- compare metrics across model/data versions;
- document any manual relabeling.

### 2. Data leakage and invalid evaluation

**Scenario:** identifiers, duplicated flows, future-derived features, or preprocessing fitted on the full dataset leak information into the test set.

**Impact:** inflated metrics that do not generalize.

**Planned mitigations:**

- fit preprocessing only on training data;
- use group/time-aware splitting when data collection structure requires it;
- review raw identifiers before including them as predictive features;
- report class distribution for each split;
- inspect duplicates across splits;
- keep a held-out test set untouched until final evaluation.

### 3. Adversarial evasion

**Scenario:** an attacker modifies mutable flow characteristics while preserving the underlying malicious objective.

**Impact:** false negatives and misplaced analyst confidence.

**Planned evaluation:**

- explicitly distinguish mutable and immutable features;
- define feasible perturbation bounds;
- measure robust recall under constrained perturbations;
- compare baseline and adversarially trained models when implemented;
- report attack success rate alongside normal test metrics.

### 4. Alert flooding

**Scenario:** a host generates high-volume activity that repeatedly satisfies detection criteria.

**Impact:** analyst fatigue, database growth, and reduced visibility of important alerts.

**Planned mitigations:**

- rate-aware alert aggregation;
- duplicate suppression;
- transparent incident-correlation windows;
- per-source/per-technique alert statistics;
- retain raw counts so suppression does not erase evidence.

### 5. Misleading risk severity

**Scenario:** model probability is treated as synonymous with incident severity.

**Impact:** low-impact but high-confidence anomalies may be over-prioritized, while lower-confidence high-impact activity may be missed.

**Design rule:** probability, rule evidence, asset context, repeated behavior, and business impact must remain separate concepts. A future risk score must document its formula and component weights.

### 6. Explanation manipulation or over-trust

**Scenario:** an explanation is technically correct for the model but interpreted as proof of malicious intent, or small feature changes alter the top explanation while leaving the prediction unchanged.

**Impact:** false analyst confidence and poor incident decisions.

**Planned mitigations/evaluation:**

- always show observed feature values next to explanation contributions;
- preserve the model/version that produced each explanation;
- distinguish global feature importance from local explanation;
- measure explanation stability for similar examples;
- never present SHAP output as causal proof;
- preserve access to the original event.

### 7. Model/version confusion

**Scenario:** an alert is displayed without reliable linkage to the exact preprocessing pipeline and model version that produced it.

**Impact:** irreproducible investigations and invalid comparisons.

**Planned mitigations:**

- immutable model-version identifiers;
- model metadata containing feature schema, hyperparameters, training dataset, seed, and evaluation metrics;
- store model version with every prediction;
- reject incompatible feature schemas at inference time.

### 8. Malicious file upload

**Scenario:** a user uploads an oversized, malformed, path-manipulating, or unexpected file.

**Impact:** denial of service, parser exploitation, file overwrite, or accidental processing of unsupported content.

**Planned mitigations:**

- explicit file-size limits;
- extension and content-type checks where appropriate;
- generated server-side filenames;
- path normalization and directory confinement;
- parser time/resource limits;
- reject unsupported schemas rather than guessing silently.

### 9. Prompt injection in a future AI assistant

**Scenario:** retrieved evidence contains text such as "ignore previous instructions" and the model treats that content as privileged instructions.

**Impact:** ungrounded analysis, inappropriate tool use, or disclosure of unrelated context.

**Required design principles for the future milestone:**

- retrieved content is data, never trusted instruction;
- the assistant receives only the minimum incident context required;
- secrets must never be placed in model prompts;
- tool authorization is enforced by deterministic application code;
- tool parameters are schema-validated and allowlisted;
- generated conclusions cite the exact stored evidence they use;
- unavailable evidence must produce an explicit "not available" response rather than fabrication;
- model output is treated as untrusted until validated by the application and/or analyst.

### 10. False or overconfident ATT&CK mapping

**Scenario:** a model or rule maps an event to a MITRE ATT&CK technique without enough evidence.

**Impact:** analysts may infer attacker intent or behavior that the data does not actually demonstrate.

**Design rule:** mappings should be phrased as hypotheses such as "potentially consistent with T1046" unless stronger evidence exists. Each mapping should store its reason and evidence level.

## Security controls by milestone

| Control | Current status |
|---|---|
| Synthetic demo data clearly labeled | Implemented in Milestone 1 |
| Deterministic demo labels separated from ML claims | Implemented in Milestone 1 |
| PostgreSQL/SQLite persistence | Implemented in Milestone 1 |
| CSV/schema validation | Planned |
| Upload size/type restrictions | Planned |
| Dataset provenance/checksums | Planned |
| Trained model registry/versioning | Planned |
| Leakage-aware evaluation pipeline | Planned |
| SHAP explanation tracking | Planned |
| Adversarial robustness evaluation | Planned |
| Evidence-backed ATT&CK mapping | Planned |
| Analyst authentication/authorization hardening | Planned |
| Grounded LLM assistant | Planned |
| Tool-level deterministic authorization | Planned |

This table should be updated whenever a mitigation is actually implemented.

## Research-specific validation checklist

Before publishing model results, verify that:

- the dataset source and license are documented;
- train/validation/test separation is reproducible;
- preprocessing is fitted without test leakage;
- class imbalance is reported;
- precision, recall, F1, confusion matrix, and appropriate PR/ROC metrics are recorded;
- false positives and false negatives are inspected, not just counted;
- the model version and feature schema are immutable for the reported experiment;
- synthetic/demo data are never mixed with reported experimental results;
- robustness limitations are stated explicitly;
- explanations are presented as model-behavior evidence, not causal proof.

## Residual risk

Even after the planned controls are implemented, several risks remain:

- network datasets may not represent future environments;
- labels may be incomplete or ambiguous;
- adversaries can adapt to known feature sets;
- explanation methods can be unstable or misleading when interpreted causally;
- an LLM can still produce incorrect language even when grounded in correct evidence;
- defensive automation can amplify mistakes if authorization and human review are weak.

Accordingly, this project treats ML and LLM components as decision-support mechanisms. Final security conclusions should remain evidence-based and reviewable by a human analyst.
