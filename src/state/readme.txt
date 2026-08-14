NEXSIZ :: state

Hybrid state awareness and transition prediction.

StateTracker records observed response/coverage signatures
and edges between them. StatePredictor maintains lightweight
rarity statistics used to bias corpus energy.

Feeds the scheduling loop so the fuzzer prefers transitions
that historically produced new behaviour.
