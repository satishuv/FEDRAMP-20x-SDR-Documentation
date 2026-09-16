# Class C end-to-end sample and assessor attack (fictional)

This directory drives a fully-worked, FICTIONAL Class C offering ("Beacon
Federal Cloud", BFC) all the way to a submission-preflight-ready package, then
attacks that package the way an independent assessor would - trying to make a
substantively incomplete package still reach "ready".

Everything here is fictional. No real PII, account IDs, assessors, or evidence.
A green preflight means the framework's readiness checks are SATISFIABLE by
complete input, NOT that anything is FedRAMP compliant. Compliance is the
accredited assessor's and the program's determination.

## Why this exists

The Class B sample (`examples/sample-offering`) fills narrative only and leaves
status/tests/evidence as template, so it never exercises the Class C readiness
gates on POPULATED data. Class C adds the hardest gates: >= 2 automated methods
per KSI (FRC-CSX-VVK), a >= 6-month persistent-validation history (FRC-CSX-MOT),
evidence linkage for every applicable MUST, a fresh FedRAMP Recognized
independent assessment (FRC-APP-FIA), availability reporting (CDS-CSO-AVR), a
structurally complete CPO, and a manifest-bound signoff. Bugs hide precisely
where nothing populated flows through.

## Run it

```bash
# Fill a complete Class C package and run package-preflight (expects READY):
python examples/sample-offering-class-c/build_class_c_sample.py

# Assessor attack: from the READY package, apply one hollowing tamper at a time
# and assert preflight BLOCKS each (a tamper that still reaches ready is a gap):
python examples/sample-offering-class-c/build_class_c_sample.py --attack
```

Both always restore the real inputs (and regenerate all class outputs) in a
finally block, so the repository is never left holding sample content.

## What the exercise found

Running a genuinely complete Class C package end-to-end surfaced defects a static
review had missed:

1. Structured `tests` crashed the human-readable build. The human-readable SDR,
   the Word export, and `explain` all did `"; ".join(tests)` assuming a list of
   strings; a structured test entry raised an unhandled `TypeError` before the
   schema validator could give the clear "ksiTests must be strings" message.
   Fixed: those renderers now coerce a structured entry to a readable string, so
   the schema validator (not a crash) reports a malformed test.

2. Ready-but-empty metric summaries (the real gap). A Class C package could reach
   "ready" with all 46 KSI historical-metric summaries (SDR-CSX-KMT, a Class C
   MUST) left as unresolved TBD: the FRC-CSX-MOT duration gate passed via the
   metric history, and the semantic check confirmed the KMT KEYS were present,
   but nothing gated the summary VALUES being empty. Fixed: preflight now treats
   an unresolved KMT summary as an unanswered-requirement blocker at the classes
   where SDR-CSX-KMT is MUST (B: 30-day + yearly; C/D: those plus a daily-data
   reference). The `--attack` harness and the offline e2e both regression-guard
   this.

The remaining assessor probes were already correctly blocked, confirming the
readiness gating is robust against those vectors. The `--attack` harness runs
one baseline (must be READY) plus 13 hollowing tampers (each must be BLOCKED):

- empty SDR-CSX-KMT historical-metric summaries (the gap above)
- an `sdr://placeholder/` evidence URI in an applicable record
- fewer than 2 automated methods per KSI (FRC-CSX-VVK at Class C)
- an independent assessment older than 9 months with no freshening
- a non-survivable availability service (`available_when_primary_unavailable` false)
- `provider_verified_at` older than 7 days (FRC-APP-FCP freshness)
- `provider_verified_at` dated in the FUTURE (must not count as fresh)
- `certification_path` set to Agency (the engine resolves Program path only)
- an FIA `completed_at` dated in the FUTURE (cannot complete in the future)
- availability history shorter than 30 days (CDS-CSO-AVR)
- a KSI "answered" with a bare `N/A` instead of an honest Not-Implemented
- a package signoff bound to the WRONG manifest SHA-256
- a package signoff whose decision is not `approved`

The two future-date probes matter specifically: a naive `now - date > 7 days`
freshness check would treat a future date as zero days old and wrongly pass, so
those probes guard against that class of bug.
