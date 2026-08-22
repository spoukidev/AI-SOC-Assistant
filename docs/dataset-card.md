# Dataset Card

## Dataset

Two synthetic resources are provided: hand-authored flow records for ingestion/UI behavior and a deterministic balanced labeled dataset generator for exercising Milestone 3 training and evaluation.

## License and source

Project-authored synthetic examples under the repository license. No packet payloads or real telemetry are included.

## Labels and limitations

Some records trigger transparent demo rules. The generated labeled dataset uses deliberately constructed benign/malicious patterns and is not real ground truth. Its metrics must not be used to report real-world ML performance. Experiment splits are stratified 70/15/15 with a recorded seed.
