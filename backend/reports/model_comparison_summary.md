# Model Comparison Summary

## Main Dataset Comparison

| model | accuracy | precision_malicious | recall_malicious | f1_malicious | roc_auc | tn | fp | fn | tp | benign_fp_rate_default | benign_fp_rate_threshold_0_90 | malicious_recall_threshold_0_90 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Gradient Boosting | 0.9831 | 0.9828 | 0.95 | 0.9661 | 0.9924 | 175 | 1 | 3 | 57 | 0.0057 | 0.0 | 0.9333 |
| Logistic Regression | 0.9619 | 0.918 | 0.9333 | 0.9256 | 0.9871 | 171 | 5 | 4 | 56 | 0.0284 | 0.017 | 0.8833 |
| SVM (RBF) | 0.9703 | 0.9344 | 0.95 | 0.9421 | 0.9718 | 172 | 4 | 3 | 57 | 0.0227 | 0.0227 | 0.8833 |
| Random Forest | 0.9831 | 0.9828 | 0.95 | 0.9661 | 0.9871 | 175 | 1 | 3 | 57 | 0.0057 | 0.0 | 0.85 |

## Held-Out Hard-Negative Benign Comparison

| model | benign_rows | false_positive_count_default | false_positive_rate_default | false_positive_count_threshold_0_90 | false_positive_rate_threshold_0_90 | max_benign_confidence |
| --- | --- | --- | --- | --- | --- | --- |
| Gradient Boosting | 21 | 0 | 0.0 | 0 | 0.0 | 0.0051 |
| Random Forest | 21 | 0 | 0.0 | 0 | 0.0 | 0.225 |
| Logistic Regression | 21 | 0 | 0.0 | 0 | 0.0 | 0.2736 |
| SVM (RBF) | 21 | 1 | 0.0476 | 0 | 0.0 | 0.6757 |

## Gradient Boosting Threshold Analysis

| threshold | main_benign_fp_rate | main_malicious_recall | main_malicious_precision | hard_negative_fp_rate |
| --- | --- | --- | --- | --- |
| 0.5 | 0.0057 | 0.95 | 0.9828 | 0.0 |
| 0.6 | 0.0057 | 0.9333 | 0.9825 | 0.0 |
| 0.7 | 0.0 | 0.9333 | 1.0 | 0.0 |
| 0.8 | 0.0 | 0.9333 | 1.0 | 0.0 |
| 0.85 | 0.0 | 0.9333 | 1.0 | 0.0 |
| 0.9 | 0.0 | 0.9333 | 1.0 | 0.0 |
| 0.95 | 0.0 | 0.9167 | 1.0 | 0.0 |
| 0.99 | 0.0 | 0.85 | 1.0 | 0.0 |

## Recommendation

- Recommended deployed model: **Gradient Boosting**.
- Selected extension block threshold: **0.90**.
- At threshold 0.90, the deployed Gradient Boosting model achieved 93.33% malicious recall on the main hold-out split while keeping the held-out hard-negative benign false-positive rate at 0.00%.
- This threshold therefore balances user-facing false-positive reduction with strong detection recall for the FYP 2 demonstration.
