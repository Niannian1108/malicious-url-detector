# Model Comparison Summary

## Main Dataset Comparison

| model | accuracy | precision_malicious | recall_malicious | f1_malicious | roc_auc | tn | fp | fn | tp | benign_fp_rate_default | benign_fp_rate_threshold_0_90 | malicious_recall_threshold_0_90 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Gradient Boosting | 0.9917 | 0.9833 | 0.9833 | 0.9833 | 0.9953 | 179 | 1 | 1 | 59 | 0.0056 | 0.0 | 0.9667 |
| SVM (RBF) | 0.9792 | 0.9365 | 0.9833 | 0.9593 | 0.9756 | 176 | 4 | 1 | 59 | 0.0222 | 0.0222 | 0.9833 |
| Logistic Regression | 0.975 | 0.9219 | 0.9833 | 0.9516 | 0.9922 | 175 | 5 | 1 | 59 | 0.0278 | 0.0167 | 0.95 |
| Random Forest | 0.9875 | 0.9672 | 0.9833 | 0.9752 | 0.9896 | 178 | 2 | 1 | 59 | 0.0111 | 0.0 | 0.9167 |

## Hard-Negative Benign Comparison

| model | benign_rows | false_positive_count_default | false_positive_rate_default | false_positive_count_threshold_0_90 | false_positive_rate_threshold_0_90 | max_benign_confidence |
| --- | --- | --- | --- | --- | --- | --- |
| Gradient Boosting | 42 | 0 | 0.0 | 0 | 0.0 | 0.0045 |
| Random Forest | 42 | 0 | 0.0 | 0 | 0.0 | 0.135 |
| Logistic Regression | 42 | 0 | 0.0 | 0 | 0.0 | 0.146 |
| SVM (RBF) | 42 | 1 | 0.0238 | 0 | 0.0 | 0.571 |

## Gradient Boosting Threshold Analysis

| threshold | main_benign_fp_rate | main_malicious_recall | main_malicious_precision | hard_negative_fp_rate |
| --- | --- | --- | --- | --- |
| 0.5 | 0.0056 | 0.9833 | 0.9833 | 0.0 |
| 0.6 | 0.0056 | 0.9667 | 0.9831 | 0.0 |
| 0.7 | 0.0 | 0.9667 | 1.0 | 0.0 |
| 0.8 | 0.0 | 0.9667 | 1.0 | 0.0 |
| 0.85 | 0.0 | 0.9667 | 1.0 | 0.0 |
| 0.9 | 0.0 | 0.9667 | 1.0 | 0.0 |
| 0.95 | 0.0 | 0.9333 | 1.0 | 0.0 |
| 0.99 | 0.0 | 0.8333 | 1.0 | 0.0 |

## Recommendation

- Recommended deployed model: **Gradient Boosting**.
- Selected extension block threshold: **0.90**.
- At threshold 0.90, the deployed Gradient Boosting model achieved 96.67% malicious recall on the main hold-out split while keeping the curated hard-negative benign false-positive rate at 0.00%.
- This threshold therefore balances user-facing false-positive reduction with strong detection recall for the FYP 2 demonstration.
