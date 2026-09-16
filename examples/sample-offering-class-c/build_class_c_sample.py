#!/usr/bin/env python3
"""Build a fully-worked FICTIONAL Class C sample and drive it to submission
preflight, so the HARDEST gates are exercised end-to-end: >=2 automated methods
per KSI (FRC-CSX-VVK), a >=6-month persistent-validation history (FRC-CSX-MOT),
evidence linkage for every applicable MUST, a fresh FedRAMP Recognized
independent assessment (FRC-APP-FIA), availability reporting (CDS-CSO-AVR), a
structurally complete CPO, and a manifest-bound human signoff.

WHY: the Class B sample (examples/sample-offering) fills narrative only and
leaves status/tests/evidence as template, so it never exercises the Class C
readiness gates on POPULATED data. That is exactly where subtle bugs hide (e.g.
the series-vs-list MOT bug). This builder fills a realistic, messy, COMPLETE
Class C package and runs package-preflight against it.

Everything is FICTIONAL. No real PII, account IDs, assessors, or evidence. This
is illustrative example data, not an attestation and not evidence of compliance.
A green preflight here means the framework's readiness checks are SATISFIABLE by
complete input, NOT that anything is FedRAMP compliant.

Run:
    python examples/sample-offering-class-c/build_class_c_sample.py          # run preflight
    python examples/sample-offering-class-c/build_class_c_sample.py --attack # adversarial probes
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import datetime as dt

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(os.path.dirname(HERE))
REAL_STORE = os.path.join(BASE, "sdr", "records", "records-store.json")
REAL_PROFILE = os.path.join(BASE, "profiles", "common", "offering-profile.json")
REAL_HISTORY = os.path.join(BASE, "automation", "metrics", "metric-history.json")
MANIFEST = os.path.join(BASE, "artifacts", "release-manifest.json")

TODAY = dt.date.today()
FICT = "[SAMPLE - fictional, not an attestation]"


def _impl(kid, aspect):
    return (f"{FICT} Beacon Federal Cloud (BFC) addresses {kid} for '{aspect}' via "
            "documented, version-controlled controls in the BFC boundary, deployed "
            "by CI/CD and continuously monitored in AWS Security Hub and Config. "
            "Illustrative example text only.")


def fill_ksi(kid, rec):
    """Fill a KSI record to Class C readiness: Implemented status, real
    narratives, TWO automated verification methods, and a resolvable evidence
    entry. Fictional but structurally complete."""
    rec["implementation_status"] = "Implemented"
    rec["implementation"] = [_impl(kid, "implementation")]
    rec["validation"] = [_impl(kid, "validation")]
    rec["assessment"] = [f"{FICT} Independently assessed by the fictional Recognized "
                         "assessor as part of the BFC FedRAMP 20x assessment."]
    # FRC-CSX-VVK Class C: >= 2 automated methods per KSI. The official SDR
    # schema's ksiTests is an ARRAY OF STRINGS, so record each method as a
    # descriptive string (not a structured object).
    rec["tests"] = [
        f"{FICT} Automated (continuous): AWS Config managed+custom rules "
        f"evaluate {kid} state; non-compliant results alarm to Security Hub.",
        f"{FICT} Automated (daily): a scheduled CodeBuild collector queries the "
        f"relevant read-only AWS APIs for {kid} and records a datapoint.",
    ]
    # One resolvable evidence entry (has a real location + source fact + hash is
    # computed by the build; here we give a concrete non-placeholder location).
    rec["evidence"] = [{
        "evidenceType": "Configuration",
        "evidenceDescription": f"{FICT} Security Hub + Config evaluation history for {kid}.",
        "evidenceLocation": f"https://evidence.bfc-demo.invalid/{kid.lower()}/latest.json",
        "lastUpdated": TODAY.isoformat(),
    }]
    ext = rec.setdefault("extension", {})
    for f in list(ext.keys()):
        v = ext[f]
        if isinstance(v, str) and ("TBD" in v or not v.strip()):
            ext[f] = _impl(kid, f)
        elif isinstance(v, list) and (not v or all("TBD" in str(x) for x in v)):
            ext[f] = [_impl(kid, f)]
    ext["owner"] = "J. Rivera, BFC Security Engineering (fictional)"
    ext["measures_verification"] = _impl(kid, "measures_verification")
    ext["automation_verification"] = _impl(kid, "automation_verification")
    # SDR-CSX-KMT historical-metric summaries (Class C MUST): 30-day, up-to-one-
    # year, and a daily-data reference. Fictional sample values.
    hm = rec.setdefault("historical_metrics", {})
    hm["last_30_days"] = f"{FICT} {kid}: 30/30 days passing over the last 30 days."
    hm["up_to_one_year"] = f"{FICT} {kid}: >=99% passing across the available ~7-month window."
    hm["daily_data_reference"] = f"https://evidence.bfc-demo.invalid/{kid.lower()}/daily-metrics.json"
    return rec


def fill_frr(rid, rec):
    rec["implementation_status"] = "Implemented"
    rec["implementation"] = [_impl(rid, "implementation")]
    rec["validation"] = [_impl(rid, "validation")]
    rec["assessment"] = [f"{FICT} Independently verified and validated for {rid}."]
    ext = rec.setdefault("extension", {})
    for f in list(ext.keys()):
        v = ext[f]
        if isinstance(v, str) and ("TBD" in v or not v.strip()):
            ext[f] = _impl(rid, f)
        elif isinstance(v, list) and (not v or all("TBD" in str(x) for x in v)):
            ext[f] = [_impl(rid, f)]
    ext["owner"] = "J. Rivera, BFC Security Engineering (fictional)"
    ext["independent_verification"] = f"{FICT} Independent verification recorded for {rid}."
    ext["independent_validation"] = f"{FICT} Independent validation recorded for {rid}."
    # A resolvable rule artifact so evidence-linkage is satisfied for populated MUSTs.
    ext["rule_artifacts"] = [{
        "evidenceType": "Configuration",
        "evidenceDescription": f"{FICT} Control evidence for {rid}.",
        "evidenceLocation": f"https://evidence.bfc-demo.invalid/frr/{rid.lower()}.json",
        "lastUpdated": TODAY.isoformat(),
    }]
    return rec


def generate_store():
    with open(REAL_STORE, encoding="utf-8") as f:
        store = json.load(f)
    for kid, rec in store.get("ksi", {}).items():
        fill_ksi(kid, rec)
    for rid, rec in store.get("frr", {}).items():
        fill_frr(rid, rec)
    return store


def generate_history(store):
    """A >=6-month daily-ish metric history per KSI, in the REAL production
    shape append_metrics writes: {"ksis": {kid: {"series": [{date,status}...]}}}."""
    ksis = list(store.get("ksi", {}).keys())
    hist = {"ksis": {}}
    for kid in ksis:
        series = []
        # 200 days back to today, weekly datapoints (well over the 183-day min).
        d = TODAY - dt.timedelta(days=200)
        while d <= TODAY:
            series.append({"date": d.isoformat(), "status": "pass"})
            d += dt.timedelta(days=7)
        hist["ksis"][kid] = {"series": series}
    return hist


def _norm_key(text):
    import re
    base = re.split(r"\(", str(text))[0].strip().lower()
    return re.sub(r"[^a-z0-9]+", "_", base).strip("_")


def _cr26_following(rid):
    import re
    ds = json.load(open(os.path.join(BASE, "references",
                                     "fedramp-consolidated-rules.json"), encoding="utf-8"))

    def find(node, target):
        if isinstance(node, dict):
            if target in node:
                return node[target]
            for v in node.values():
                r = find(v, target)
                if r is not None:
                    return r
        elif isinstance(node, list):
            for v in node:
                r = find(v, target)
                if r is not None:
                    return r
        return None

    return (find(ds, rid) or {}).get("following_information", []) or []


def _cpo_required_information(class_c_profile_rules):
    """Build the CPO-CSO-OVR required-information map for the applicable rules,
    derived from the dataset so it is correct by construction. Objects for
    CDS-CSO-PUB (keyed by its following_information items), arrays for
    CDS-CSO-IRP / MAS-CSO-TPR, scalars for the rest."""
    OBJECT_RULES = {"CDS-CSO-PUB"}
    ARRAY_RULES = {"CDS-CSO-IRP", "MAS-CSO-TPR"}
    # The full CPO-CSO-OVR referenced set; the CPO builder keeps only those
    # applicable to the class.
    OVR_RULES = ["CPO-CSO-MTD", "CDS-CSO-PUB", "CDS-CSO-SVC", "CDS-CSO-IRP",
                 "MAS-CSO-IIR", "MAS-CSO-FLO", "MAS-CSO-TPR", "CMU-CSO-CMD",
                 "IVV-CSO-ICP"]
    out = {"note": "CPO-CSO-OVR required information (fictional sample content)."}
    for rid in OVR_RULES:
        if rid in OBJECT_RULES:
            items = _cr26_following(rid)
            out[rid] = {_norm_key(x): f"{FICT} {rid}: {str(x)[:80]}"
                        for x in items} or {"summary": f"{FICT} {rid} content."}
        elif rid in ARRAY_RULES:
            fields = _cr26_following(rid)
            rec = {_norm_key(x): f"{FICT} {str(x)[:80]}" for x in fields}
            if not rec:
                rec = {"summary": f"{FICT} {rid} record."}
            out[rid] = [rec]
        else:
            out[rid] = f"{FICT} {rid}: provider information supplied in the CPO."
    return out


def generate_profile():
    with open(REAL_PROFILE, encoding="utf-8") as f:
        profile = json.load(f)
    recent = (TODAY - dt.timedelta(days=2)).isoformat()
    fia_done = (TODAY - dt.timedelta(days=40)).isoformat()  # < 3 months, no freshening needed
    profile.update({
        "organization_name": "Beacon Federal Cloud, Inc. (fictional)",
        "offering_name": "Beacon Federal Cloud",
        "offering_abbreviation": "BFC",
        "business_purpose": ("A fictional multi-tenant SaaS data-processing platform, "
                             "used to demonstrate a COMPLETE Class C package."),
        "service_model": "SaaS",
        "deployment_model": "Public Cloud",
        "certification_type": "20x",
        "certification_class": "C",
        "certification_path": "Program",
        "aws_partition": "aws",
        "primary_region": "us-east-1",
        "dr_region": "us-west-2",
        "management_plane": "Provider-hosted control plane, isolated from customer workloads (fictional).",
        "federal_information_types": "Illustrative example only; no real federal data.",
        "certification_package_overview_uri": "https://trust.bfc-demo.invalid/cpo.json",
        "security_contact": "security@bfc-demo.invalid (fictional)",
        "incident_contact": "ir@bfc-demo.invalid (fictional)",
        "sales_contact": "sales@bfc-demo.invalid (fictional)",
        "assessor": "Cascade Assurance LLC (fictional Recognized assessor)",
        "assessor_id": "123456",
        "evidence_retention": "13 months rolling (fictional sample policy).",
        "provider_verified_at": recent + "T00:00:00+00:00",
        "overall_assessment_summary": (f"{FICT} The independent assessor's overall summary: "
                                       "no unresolved high findings; all in-scope KSIs validated."),
        "fedramp_independent_assessment": {
            "assessor_name": "Cascade Assurance LLC (fictional)",
            "assessor_fedramp_id": "FR-RECOG-0142 (fictional)",
            "completed_at": fia_done,
        },
        "availability_reporting": {
            "human_readable_uri": "https://trust.bfc-demo.invalid/status",
            "machine_readable_uri": "https://trust.bfc-demo.invalid/status.json",
            "history_days": 120,
            "available_when_primary_unavailable": True,
        },
        "trust_center_uri": "https://trust.bfc-demo.invalid/",
        "secure_config_guide_uri": "https://trust.bfc-demo.invalid/scg",
        "next_ocr_date": (TODAY + dt.timedelta(days=80)).isoformat(),
        # CPO metadata (CPO-CSO-MTD).
        "cpo_responsible_official": "D. Okafor, BFC Authorizing Official (fictional)",
        "cpo_version": "1.0.0",
        "cpo_last_updated": recent,
        "cpo_source_of_update": "BFC compliance engineering (fictional)",
        # CPO placeholder-driving fields (clear the CPO template markers).
        "fedramp_package_id": "FR-20X-BFC-0001 (fictional)",
        "offering_website": "https://www.bfc-demo.invalid/",
        "offering_logo_uri": "https://www.bfc-demo.invalid/logo.png",
        "cpo_required_information": _cpo_required_information(None),
    })
    # Fill any remaining TBD scalar fields.
    for k, v in list(profile.items()):
        if isinstance(v, str) and "TBD" in v:
            profile[k] = f"{FICT} {k} for Beacon Federal Cloud."
    profile["profile_note"] = f"{FICT} FICTIONAL Class C sample; illustrative only."
    return profile


def _preflight_rc(store, profile, history, post_sign=None):
    """Apply the given in-memory inputs, build, sign, run package-preflight,
    return (returncode, output). Always restores real inputs after. If post_sign
    is given, it is called after the (correct) signoff is written and before
    preflight runs, so a probe can tamper with the manifest-bound signoff."""
    tmp = tempfile.mkdtemp(prefix="sdr-attack-")
    baks = {}
    for real in (REAL_STORE, REAL_PROFILE, REAL_HISTORY):
        if os.path.exists(real):
            b = os.path.join(tmp, os.path.basename(real) + ".bak")
            shutil.copy2(real, b)
            baks[real] = b
    history_existed = os.path.exists(REAL_HISTORY)
    try:
        json.dump(store, open(REAL_STORE, "w", encoding="utf-8", newline="\n"), indent=1)
        json.dump(profile, open(REAL_PROFILE, "w", encoding="utf-8", newline="\n"), indent=1)
        json.dump(history, open(REAL_HISTORY, "w", encoding="utf-8", newline="\n"), indent=1)
        subprocess.run([sys.executable, os.path.join(BASE, "sdr.py"), "build"],
                       cwd=BASE, capture_output=True, text=True)
        _record_signoff()
        if post_sign is not None:
            post_sign()
        pf = subprocess.run([sys.executable, os.path.join(BASE, "sdr.py"), "package-preflight"],
                            cwd=BASE, capture_output=True, text=True)
        return pf.returncode, (pf.stdout or "") + (pf.stderr or "")
    finally:
        for real, b in baks.items():
            shutil.copy2(b, real)
        if not history_existed and os.path.exists(REAL_HISTORY):
            os.remove(REAL_HISTORY)
        subprocess.run(["git", "-C", BASE, "checkout", "--",
                        "sdr/reviews/review-register.json"], capture_output=True, text=True)
        shutil.rmtree(tmp, ignore_errors=True)
        # Regenerate ALL class outputs from the restored real inputs, so sample
        # content never lingers in a committed inactive-class SDR (build alone
        # only regenerates the active class).
        for c in ("a", "c"):
            env = dict(os.environ, SDR_BUILD_CLASS=c)
            subprocess.run([sys.executable, os.path.join(BASE, "validation", "scripts", "build_sdr.py")],
                           cwd=BASE, capture_output=True, text=True, env=env)
        subprocess.run([sys.executable, os.path.join(BASE, "sdr.py"), "build"],
                       cwd=BASE, capture_output=True, text=True)


def attack():
    """Assessor attack: start from the READY Class C package, apply one hollowing
    tamper at a time, and assert preflight BLOCKS each. A tamper that still
    reaches 'ready' is a framework gap."""
    import copy
    base_store = generate_store()
    base_profile = generate_profile()
    base_history = generate_history(base_store)
    passed = failed = 0

    def probe(name, mutate, post_sign=None):
        nonlocal passed, failed
        st, pr, hi = copy.deepcopy(base_store), copy.deepcopy(base_profile), copy.deepcopy(base_history)
        mutate(st, pr, hi)
        rc, _out = _preflight_rc(st, pr, hi, post_sign=post_sign)
        blocked = rc != 0
        if blocked:
            passed += 1; print(f"  PASS (blocked) {name}")
        else:
            failed += 1; print(f"  FAIL (reached READY despite tamper) {name}")

    # Baseline: the unmutated package must be READY (else the probes are meaningless).
    rc0, _ = _preflight_rc(copy.deepcopy(base_store), copy.deepcopy(base_profile),
                           copy.deepcopy(base_history))
    if rc0 == 0:
        passed += 1; print("  PASS (ready) baseline complete package is READY")
    else:
        failed += 1; print("  FAIL baseline package is not READY (attack invalid)")

    # 1. Empty the KMT summaries -> must block (the gap this exercise found).
    def _empty_kmt(st, pr, hi):
        for rec in st["ksi"].values():
            rec["historical_metrics"] = {"last_30_days": "TBD: Information has not been provided.",
                                         "up_to_one_year": "TBD: Information has not been provided.",
                                         "daily_data_reference": "TBD: Information has not been provided."}
    probe("empty SDR-CSX-KMT summaries block at Class C", _empty_kmt)

    # 2. Point evidence at an sdr://placeholder/ location -> must block.
    def _placeholder_evidence(st, pr, hi):
        for rec in st["ksi"].values():
            for e in rec.get("evidence", []):
                e["evidenceLocation"] = "sdr://placeholder/replace-me"
    probe("placeholder evidence URI blocks", _placeholder_evidence)

    # 3. Drop to one automated method per KSI -> Class C requires 2, must block.
    def _one_method(st, pr, hi):
        for rec in st["ksi"].values():
            rec["tests"] = rec.get("tests", [])[:1]
    probe("< 2 automated methods per KSI blocks at Class C", _one_method)

    # 4. Stale FIA (> 9 months, no freshening) -> must block.
    def _stale_fia(st, pr, hi):
        pr["fedramp_independent_assessment"]["completed_at"] = (
            TODAY - dt.timedelta(days=400)).isoformat()
    probe("FIA older than 9 months blocks", _stale_fia)

    # 5. Availability service not survivable -> must block.
    def _avr_not_survivable(st, pr, hi):
        pr["availability_reporting"]["available_when_primary_unavailable"] = False
    probe("non-survivable availability service blocks", _avr_not_survivable)

    # 6. Provider verification older than 7 days -> FRC-APP-FCP freshness, block.
    def _stale_verification(st, pr, hi):
        pr["provider_verified_at"] = (
            TODAY - dt.timedelta(days=30)).isoformat() + "T00:00:00+00:00"
    probe("provider_verified_at older than 7 days blocks", _stale_verification)

    # 7. Provider verification dated in the FUTURE -> must not be accepted as
    #    "within the previous 7 days"; a future date is not a valid verification.
    def _future_verification(st, pr, hi):
        pr["provider_verified_at"] = (
            TODAY + dt.timedelta(days=5)).isoformat() + "T00:00:00+00:00"
    probe("future-dated provider_verified_at does not pass freshness", _future_verification)

    # 8. certification_path Agency -> the engine resolves Program-path only,
    #    so an Agency-path claim must block (wrong applicability scope).
    def _agency_path(st, pr, hi):
        pr["certification_path"] = "Agency"
    probe("Agency certification_path blocks (Program-path engine)", _agency_path)

    # 9. FIA completed_at in the FUTURE -> an assessment cannot complete in the
    #    future; must block rather than count as fresh.
    def _future_fia(st, pr, hi):
        pr["fedramp_independent_assessment"]["completed_at"] = (
            TODAY + dt.timedelta(days=20)).isoformat()
    probe("future-dated FIA completed_at blocks", _future_fia)

    # 10. Availability history < 30 days -> CDS-CSO-AVR requires >= 30, block.
    def _short_avr_history(st, pr, hi):
        pr["availability_reporting"]["history_days"] = 10
    probe("availability history < 30 days blocks (CDS-CSO-AVR)", _short_avr_history)

    # 11. A KSI "answered" with a hollow N/A instead of an honest Not-Implemented
    #     with rationale -> must be treated as unanswered and block. This is the
    #     "impossible to fool with a non-answer" property for a KSI.
    def _hollow_na_ksi(st, pr, hi):
        first = next(iter(st["ksi"].values()))
        first["implementation"] = ["N/A"]
        first.setdefault("extension", {})["measures"] = "N/A"
        first["extension"]["measures_verification"] = "N/A"
    probe("a KSI answered with bare 'N/A' is not accepted as answered", _hollow_na_ksi)

    # 12. Manifest-bound signoff with the WRONG manifest SHA -> a signoff that
    #     does not bind the exact built manifest must block (tamper AFTER signing).
    def _noop(st, pr, hi):
        pass

    def _corrupt_signoff_sha():
        import json as _j
        reg_path = os.path.join(BASE, "sdr", "reviews", "review-register.json")
        reg = _j.load(open(reg_path, encoding="utf-8"))
        reg["package_signoff"]["package_manifest_sha256"] = "sha256:" + ("0" * 64)
        _j.dump(reg, open(reg_path, "w", encoding="utf-8", newline="\n"), indent=1)
    probe("signoff bound to the WRONG manifest SHA blocks", _noop,
          post_sign=_corrupt_signoff_sha)

    # 13. Signoff decision not 'approved' -> a rejected/pending signoff cannot
    #     make a package ready.
    def _reject_signoff():
        import json as _j
        reg_path = os.path.join(BASE, "sdr", "reviews", "review-register.json")
        reg = _j.load(open(reg_path, encoding="utf-8"))
        reg["package_signoff"]["decision"] = "rejected"
        _j.dump(reg, open(reg_path, "w", encoding="utf-8", newline="\n"), indent=1)
    probe("a non-approved package_signoff blocks", _noop, post_sign=_reject_signoff)

    print(f"\n{passed}/{passed + failed} assessor-attack probes passed "
          "(each tamper must be BLOCKED; baseline must be READY)")
    return 0 if failed == 0 else 1


def run(argv):
    tmp = tempfile.mkdtemp(prefix="sdr-classc-")
    baks = {}
    for real in (REAL_STORE, REAL_PROFILE, REAL_HISTORY):
        if os.path.exists(real):
            b = os.path.join(tmp, os.path.basename(real) + ".bak")
            shutil.copy2(real, b)
            baks[real] = b
    # Build ALL sample content in memory BEFORE any write, so a partial write
    # cannot corrupt a file a later generator reads.
    store = generate_store()
    profile = generate_profile()
    history = generate_history(store)
    history_existed = os.path.exists(REAL_HISTORY)
    try:
        with open(REAL_STORE, "w", encoding="utf-8", newline="\n") as f:
            json.dump(store, f, indent=1)
        with open(REAL_PROFILE, "w", encoding="utf-8", newline="\n") as f:
            json.dump(profile, f, indent=1)
        with open(REAL_HISTORY, "w", encoding="utf-8", newline="\n") as f:
            json.dump(history, f, indent=1)
        # Build first so generated artifacts + manifest reflect the sample.
        subprocess.run([sys.executable, os.path.join(BASE, "sdr.py"), "build"],
                       cwd=BASE, capture_output=True, text=True)
        # Record a package signoff bound to the freshly-built manifest hash.
        _record_signoff()
        pf = subprocess.run([sys.executable, os.path.join(BASE, "sdr.py"), "package-preflight"],
                            cwd=BASE, capture_output=True, text=True)
        print((pf.stdout or "") + (pf.stderr or ""))
        print(f"\nClass C package-preflight exit code: {pf.returncode} "
              f"({'READY' if pf.returncode == 0 else 'BLOCKED'})")
        return pf.returncode
    finally:
        for real, b in baks.items():
            shutil.copy2(b, real)
        # metric-history.json is git-excluded telemetry; if it did not exist
        # before, remove the sample one so the tree is left as found.
        if not history_existed and os.path.exists(REAL_HISTORY):
            os.remove(REAL_HISTORY)
        # Restore the review register too (signoff is sample-only).
        subprocess.run(["git", "-C", BASE, "checkout", "--",
                        "sdr/reviews/review-register.json"],
                       capture_output=True, text=True)
        shutil.rmtree(tmp, ignore_errors=True)
        # Regenerate ALL class outputs from the restored real inputs, so sample
        # content never lingers in a committed inactive-class SDR (build alone
        # only regenerates the active class).
        for c in ("a", "c"):
            env = dict(os.environ, SDR_BUILD_CLASS=c)
            subprocess.run([sys.executable, os.path.join(BASE, "validation", "scripts", "build_sdr.py")],
                           cwd=BASE, capture_output=True, text=True, env=env)
        subprocess.run([sys.executable, os.path.join(BASE, "sdr.py"), "build"],
                       cwd=BASE, capture_output=True, text=True)


def _record_signoff():
    """Write a package_signoff into the review register, bound to the current
    release manifest's tag AND its exact SHA-256 (the binding preflight checks).
    Fictional signer; illustrative only."""
    import hashlib
    register_path = os.path.join(BASE, "sdr", "reviews", "review-register.json")
    manifest = json.load(open(MANIFEST, encoding="utf-8"))
    with open(MANIFEST, "rb") as f:
        manifest_sha = "sha256:" + hashlib.sha256(f.read()).hexdigest()
    register = {}
    if os.path.exists(register_path):
        register = json.load(open(register_path, encoding="utf-8"))
    register["package_signoff"] = {
        "decision": "approved",
        "reviewer": "D. Okafor, BFC Authorizing Official (fictional)",
        "timestamp": TODAY.isoformat(),
        "release_tag": manifest.get("release_tag"),
        "package_manifest_sha256": manifest_sha,
        "note": f"{FICT} Package-level provider signoff for the Class C sample.",
    }
    with open(register_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(register, f, indent=1)
    return None


if __name__ == "__main__":
    if "--attack" in sys.argv:
        sys.exit(attack())
    sys.exit(run(sys.argv))
