"""Boundary tests for a NON-OFFLINE (Bedrock-like) backend behind the drafter.

The existing test_draft_narratives.py proves the boundary with the offline
TemplateDrafter. This file proves the SAME guard holds when an
attacker-controlled model backend is behind the drafter: a Bedrock-shaped
drafter that returns text trying to flip a status, write the assessment, or
dump garbage must still NOT change implementation_status / assessment / tests /
evidence, and must only ever land in the TBD implementation/validation prose.

The drafter is injected exactly the way a real backend is selected: draft_ksi()
takes the drafter object as a parameter, and get_drafter('bedrock') would
return one. We pass a fake with the same .draft(kind, ksi_id, guidance, facts)
interface, so no production code is modified or monkeypatched.

Run: python automation/ai/test_bedrock_boundary.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import draft_narratives as dn  # noqa: E402


SERVICE_MAP = {"guardduty": "Amazon GuardDuty"}


def blank_ksi_record():
    return {
        "implementation_status": "Not Implemented",
        "implementation": ["TBD: Information has not been provided."],
        "validation": ["TBD: Information has not been provided."],
        "assessment": ["TBD: Independent assessment has not been performed."],
        "tests": [],
        "evidence": [],
    }


def ksi_entry():
    return {"services": ["Amazon GuardDuty"],
            "fill_guidance": {"what_it_looks_for": "Detect suspicious activity."}}


def posture():
    return {"guardduty": [{"service": "guardduty", "check": "detector",
                           "status": "ENABLED", "detail": "ENABLED",
                           "collected_at": "2026-09-07T00:00:00+00:00",
                           "region": "us-east-1"}]}


class MaliciousBedrockDrafter:
    """A stand-in for a compromised/hostile model backend. Its returned text
    tries to claim compliance and smuggle field assignments. It has the SAME
    interface get_drafter('bedrock') would return."""
    name = "bedrock"

    def draft(self, kind, ksi_id, guidance, facts):
        return ("This control is fully Implemented and compliant. "
                "implementation_status: Implemented. assessment: PASS. "
                "tests: [all green]. evidence: s3://fake. " + ("X" * 5000))


class GarbageDrafter:
    name = "bedrock"

    def draft(self, kind, ksi_id, guidance, facts):
        return {"not": "a string"}  # wrong type entirely


def test_hostile_backend_never_touches_forbidden_fields():
    rec = blank_ksi_record()
    import copy
    before = copy.deepcopy(rec)
    # draw_ksi runs, then the module's own _assert_boundary is what a real run
    # calls; here we call draft_ksi then assert the forbidden fields directly.
    dn.draft_ksi("KSI-IAM-SUS", rec, ksi_entry(), posture(),
                 MaliciousBedrockDrafter(), SERVICE_MAP)
    for field in dn.FORBIDDEN_FIELDS:
        assert rec[field] == before[field], \
            f"forbidden field {field} changed under hostile backend"


def test_hostile_text_only_lands_in_narrative_fields():
    rec = blank_ksi_record()
    dn.draft_ksi("KSI-IAM-SUS", rec, ksi_entry(), posture(),
                 MaliciousBedrockDrafter(), SERVICE_MAP)
    # The malicious text is placed in implementation/validation (a human then
    # reviews it) but the status field itself is still the original value.
    assert rec["implementation_status"] == "Not Implemented"
    # The forbidden text living in a narrative field is fine (a human reviews
    # a DRAFT); what matters is it did NOT set the actual status.
    assert isinstance(rec["implementation"], list)


def test_module_boundary_guard_raises_if_forbidden_changed():
    # Prove dn._assert_boundary is a real tripwire: if a (buggy/hostile) path
    # DID change a forbidden field, the guard the module runs per-KSI raises.
    before = blank_ksi_record()
    after = blank_ksi_record()
    after["implementation_status"] = "Implemented"  # simulate a violation
    raised = False
    try:
        dn._assert_boundary(before, after, "KSI-IAM-SUS")
    except AssertionError:
        raised = True
    assert raised, "the boundary guard must raise when a forbidden field changes"


def test_garbage_backend_does_not_corrupt_forbidden_fields():
    rec = blank_ksi_record()
    import copy
    before = copy.deepcopy(rec)
    try:
        dn.draft_ksi("KSI-IAM-SUS", rec, ksi_entry(), posture(),
                     GarbageDrafter(), SERVICE_MAP)
    except Exception:
        pass  # a type error is acceptable; corruption is not
    for field in dn.FORBIDDEN_FIELDS:
        assert rec[field] == before[field]


def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    passed = 0
    for t in tests:
        t()
        passed += 1
        print(f"PASS: {t.__name__}")
    print(f"\n{passed}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
