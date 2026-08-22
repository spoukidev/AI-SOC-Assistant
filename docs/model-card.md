# Model Card

Milestone 3 supports Logistic Regression, Random Forest, and XGBoost artifacts trained from user-supplied labeled flow CSV files. No pretrained production model is included.

## Intended purpose

Future models will classify validated network-flow features for defensive research and analyst decision support.

## Inputs and output

Models consume the versioned `flow-v1` feature schema. Raw IP addresses are excluded. The binary output is benign (`0`) or malicious (`1`) plus the positive-class probability. Probability is not severity.

## Metrics

Metrics are stored only after a completed stratified experiment and include accuracy, precision, recall, F1, ROC-AUC, PR-AUC, TP, TN, FP, FN, and error rates. The repository does not claim a fixed performance value. Synthetic demonstration metrics are not real-world results.

## Limitations

Synthetic UI demonstrations do not establish model performance. Raw identifiers should not become predictive features without explicit justification. Distribution shift, evasion, leakage, and class imbalance require evaluation before deployment.
