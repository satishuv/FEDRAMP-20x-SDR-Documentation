#!/usr/bin/env python3
"""Apply enabled third-party evidence sources (CrowdStrike Falcon, Wiz) to the
record store, per the opt-in flags in the offering profile.

This is OPT-IN and does nothing unless a source is enabled in
profiles/common/offering-profile.json under evidence_sources. For each enabled
source it reads the customer-produced export file, runs the matching adapter,
and attaches the resulting evidence to that source's mapped KSIs in
sdr/records/records-store.json.

Trust boundary (unchanged): only the ksi `evidence` array is touched. No
implementation, validation, or assessment status is set. If a source is
enabled but its export file is absent, the source is skipped with a message,
not an error, so a fresh clone with the flag on but no export still builds.

    python automation/collectors/apply_third_party_evidence.py

Run before build_sdr.py so the attached evidence flows into the SDR. Offline:
reads only local files, no network, no credentials.
"""

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evidence_wiring as ew  # noqa: E402
import thirdparty_adapters  # noqa: E402  (registers the adapters)

PROFILE = os.path.join(BASE, "profiles", "common", "offering-profile.json")
RECORDS = os.path.join(BASE, "sdr", "records", "records-store.json")


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main():
    profile = load(PROFILE)
    sources = profile.get("evidence_sources", {})
    enabled = [(name, cfg) for name, cfg in sources.items()
               if isinstance(cfg, dict) and cfg.get("enabled")]
    if not enabled:
        print("No third-party evidence sources enabled (evidence_sources all off). "
              "Nothing to do.")
        return 0
    if not os.path.exists(RECORDS):
        print("Record store not found; run build_sdr.py once first.")
        return 1
    records = load(RECORDS)
    total_attached = 0
    for name, cfg in enabled:
        adapter = ew.get_adapter(name)
        if adapter is None:
            print(f"WARNING: enabled source '{name}' has no registered adapter; skipping.")
            continue
        export_rel = cfg.get("export_path")
        export_path = os.path.join(BASE, export_rel) if export_rel else None
        if not export_path or not os.path.exists(export_path):
            print(f"'{name}' enabled but export not found at {export_rel}; skipping. "
                  "Produce the export in your own environment (no API client here).")
            continue
        raw = load(export_path)
        evidence = adapter.to_evidence(raw)
        targets = adapter.ksi_targets()
        attached = 0
        for kid in targets:
            rec = records.get("ksi", {}).get(kid)
            if rec is None:
                continue
            existing = rec.get("evidence", []) or []
            seen = {e.get("evidenceLocation") for e in existing if isinstance(e, dict)}
            for ev in evidence:
                if ev["evidenceLocation"] in seen:
                    continue
                existing.append(ev)
                seen.add(ev["evidenceLocation"])
                attached += 1
            rec["evidence"] = existing
        total_attached += attached
        print(f"'{name}': {len(evidence)} evidence entries applied to "
              f"{len(targets)} KSI(s) ({attached} attached after de-dup).")
    if total_attached:
        with open(RECORDS, "w", encoding="utf-8", newline="\n") as f:
            json.dump(records, f, indent=1)
        print(f"Record store updated: {total_attached} evidence entries attached. "
              "Run build_sdr.py to regenerate the SDR. A human still owns the status.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
