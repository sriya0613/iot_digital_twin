# Feedback loop: incremental adaptation to a new attack (no retrain)

A 'bruteforce' attack is treated as a brand-new variant the model never trained on. The incremental model's detection of it is measured before any feedback, then after confirmed detections are streamed back (online partial_fit) - no full retrain.

| | detection rate on the new 'bruteforce' attack |
|---|---|
| before feedback (never seen it) | 0% |
| after feedback loop (online updates) | 100% |

The incremental learner adapts to the new threat from confirmed detections alone, without retraining the whole model - the 'Update Threat Database -> incremental model' feedback arrow in the architecture.
