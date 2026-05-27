# Architecture Refinement for FYP 2

## Original FYP 1 Direction

The original FYP 1 plan proposed a proxy-based malicious website detection architecture using `mitmproxy`, combined with URL, domain, and webpage-level features and multiple machine-learning model comparisons.

## Refined FYP 2 Architecture

For FYP 2, the implementation was refined into a Chrome extension plus FastAPI backend architecture:

- Chrome extension for real-time browser navigation monitoring
- FastAPI backend for feature extraction and ML inference
- Gradient Boosting deployment model selected after baseline comparison
- Threshold-based `low` / `medium` / `high` risk responses
- Lightweight DOM-assisted heuristics collected by the extension after page load
- SQLite logging for prediction history and evaluation support

## Why the Architecture Was Refined

This change should be presented as a practical refinement rather than a failure to follow the original plan.

Reasons:

1. A browser extension is more user-facing and easier to demonstrate clearly during evaluation.
2. The extension architecture still supports real-time malicious URL detection, which preserves the core project objective.
3. It avoids the operational and setup complexity of a full interception proxy for a final-year project demonstration.
4. It reduces risk around HTTPS interception, certificate handling, and browser trust configuration.
5. It allows direct control over user responses such as caution notifications, proceed-once overrides, and blocking pages.

## Academic Justification

The refinement preserves the core research problem:

- detecting malicious websites before harm occurs
- extracting explainable URL/domain-level features
- augmenting URL signals with lightweight page heuristics where practical
- applying supervised machine learning for classification
- balancing malicious recall against false positives for user safety

Therefore, the architecture changed, but the research aim remained aligned.

## Positioning in the Final Report

Suggested framing:

- FYP 1 established the broader detection concept and candidate architectures.
- During FYP 2 implementation, the browser-extension plus API design was selected as the most practical architecture for a stable prototype, controlled testing, and final demonstration.
- The refined design improved usability, observability, and deployment simplicity while still supporting real-time protection.
- Later FYP 2 iterations also added severity-based responses and lightweight DOM heuristics without abandoning the browser-extension architecture.

## Future Work / Alternative Architecture

The original `mitmproxy` idea can still be discussed as future work or an alternative architecture for deeper inspection, especially if later stages want to add:

- live HTML structural analysis
- redirect-chain inspection through a controlled proxy
- richer webpage-content features
- organization-wide gateway or network-level deployment

## Conclusion

The final FYP 2 implementation is best described as a justified engineering refinement:

- more practical to deploy
- easier to demonstrate
- safer and more stable for evaluation
- still faithful to the original project objective of real-time malicious website detection
