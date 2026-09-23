"""Single source of truth for FRC-CSX-VVK automated-method counting.

Both the authoritative validator (validate_sdr.py) and the reviewer-facing
assurance graph (build_assurance_graph.py) MUST count automated verification
methods with the exact same function. Two independent counters previously
disagreed: the validator counted distinct structured automated methods (0 for
the template records), while the graph counted raw `tests` entries (2), so the
reviewer-facing report claimed the VVK minimum was met when the authoritative
gate said it was not. Sharing this function removes that class of divergence by
construction.
"""


def count_automated_methods(tests):
    """Count DISTINCT AUTOMATED verification methods from a KSI's authoring
    `tests` list (records-store), for FRC-CSX-VVK.

    FedRAMP requires a per-class minimum of AUTOMATED methods (Class B >=1,
    C >=2, D >=4). The official SDR flattens each test to a string, losing the
    automated/manual distinction, so this must run on the authoring source.

    Counting rules, deliberately strict so the gate proves the requirement and
    is not satisfied by "there are two strings in an array":
      - Only structured entries (dicts) with automated == True count.
      - Methods must be DISTINCT: identity is method_id if present, else the
        normalized method/name/description text. Duplicates count once.
      - Plain-string entries do NOT count as automated (their automated-ness is
        unknown once flattened); they are returned separately as `string_tests`
        so a template-state record can still be reported informationally.

    Returns (automated_count, string_test_count, total_entries).
    """
    if not isinstance(tests, list):
        return 0, 0, 0
    seen = set()
    strings = 0
    total = 0
    for t in tests:
        total += 1
        if isinstance(t, str):
            strings += 1
            continue
        if isinstance(t, dict) and t.get("automated") is True:
            ident = t.get("method_id")
            if not ident:
                ident = str(t.get("method") or t.get("name")
                            or t.get("description") or "").strip().lower()
            if ident:
                seen.add(ident)
    return len(seen), strings, total
