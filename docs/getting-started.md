# Getting started

Goal: a validated Security Decision Record on your machine, and a clear picture of what to fill in next. Budget five minutes.

## Prerequisites

Python 3.10 or later, and three packages.

```bash
pip install jsonschema referencing python-docx
```

No AWS account is needed. Nothing in the build path makes a network call: the FedRAMP dataset and both official schemas are pinned in the repository.

## One command

```bash
git clone https://github.com/satishuv/FEDRAMP-20x-SDR-Documentation.git
cd FEDRAMP-20x-SDR-Documentation
python sdr.py all
```

`sdr.py` is a thin orchestrator. It runs the seven build steps in dependency order, then the validator, then the readiness scanner, then prints a summary. Available subcommands:

| Command | What it does |
|---|---|
| `python sdr.py build` | Regenerates every deliverable |
| `python sdr.py validate` | Runs the build gate only. Exit code is non-zero on a hard failure |
| `python sdr.py scan` | Runs the readiness scanner and writes findings |
| `python sdr.py all` | Build, then validate, then scan, then summarize |
| `python sdr.py clean` | Removes Python caches and scanner reports. Leaves generated deliverables alone, because they are committed on purpose |

If you have GNU make, `make build`, `make validate`, `make scan`, and `make all` wrap the same commands. `make reproducible` runs the build and then the same git diff the continuous integration gate runs.

## What you should see

The validator prints eight checks and one gating line:

```text
PASS: official_schema_validation | 0 schema errors
PASS: rule_coverage | missing: [] extra: [] (158/158 rules)
PASS: ksi_coverage | 46/46 KSIs present
PASS: ksi_required_fields | all KSIs carry the six schema-required fields
FAIL: ksi_test_minimums | 43 KSIs below the FRC-CSX-VVK minimum for class B (expected in template state; hard failure only at release)
PASS: no_markdown_in_human_readable | hits: []
PASS: no_sensitive_patterns | hits: []
PASS: content_fidelity_against_dataset | 0 mismatches (all statements, names, and forces match the dataset)
hard failures: 0
```

Then `sdr.py all` closes with a summary:

```text
Readiness summary
Certification class          Class B
Build gate                   SHIPPABLE, hard failures: 0
Checks                       7 of 8 passing
Advisory failures            ksi_test_minimums
Dataset                      deterministic check against dataset 2026.07.14.01
Assessment readiness         24.3% (531 pass, 1657 fail, 407 manual of 2595 findings)
```

That single `FAIL` line is expected and correct on a fresh clone. `FRC-CSX-VVK` sets a per-indicator automated-method target that rises by class (recommended `SHOULD` at Class B with at least one method, required `MUST` at Class C with at least two), and a template has none yet. It is reported as an advisory failure during authoring and becomes a hard failure only at release. `hard failures: 0` is the line that gates the build.

24.3 percent readiness is also the correct starting number. It measures how much of your record is filled in with facts, not how secure your system is.

## Running the steps by hand

`sdr.py` exists so you do not have to, but the order matters if you run them individually, because each step consumes the previous step's output.

| Step | Command | Why it runs here |
|---|---|---|
| 1 | `python validation/scripts/build_catalogs.py` | Extracts the rule and indicator catalogs from the pinned dataset. Everything downstream reads these |
| 2 | `python validation/scripts/build_notes.py` | Per-rule and per-indicator explainer notes, plus family name expansions. Needs the catalogs |
| 3 | `python validation/scripts/build_profiles.py` | Per-class rule profiles, the Class C overlay, the Class D readiness register. Needs catalogs and family names |
| 4 | `python validation/scripts/build_collector_registry.py` | Maps each indicator to concrete read-only AWS checks. Reads only the curated service map, so it can run at any point |
| 5 | `python validation/scripts/build_sdr.py` | The official JSON, the extensions companion, and the plain-text record. Needs profiles, notes, and your record store |
| 6 | `python validation/scripts/build_docx.py` | The authoring Word file with fill fields and inline guidance |
| 7 | `python validation/scripts/build_crosswalk.py` | The Revision 5 to 20x crosswalk, derived from the dataset's own control mappings |
| 8 | `python validation/scripts/validate_sdr.py` | The gate. Always last. Nothing ships unless this reports zero hard failures |

## Choosing your class

The repository ships set to Class B. Change one field in `profiles/common/offering-profile.json`:

```json
{
  "certification_class": "C"
}
```

Then rerun steps 5, 6, and 8, or just `python sdr.py all`. See [certification classes](certification-classes.md) for what changes between them.

## Adoption models: greenfield and brownfield

The framework never assumes how or when your offering was built. It reads whatever posture exists in the account when it runs, so it fits both a new offering and an existing one. FedRAMP's own rules do not distinguish new from existing systems; obligations are set by certification class (A to D), not by system age. Greenfield and brownfield are a practical lens, not a FedRAMP distinction.

**Greenfield** (a new offering built for 20x): add the framework at the start, so the record grows with the system and each indicator narrative is written as the capability is built. The living-SDR loop banks the up-to-one-year metric history from day one, which matters because that history cannot be backfilled. The only caveat is that a brand-new system has little posture to collect until it is actually running, so early runs correctly report many not-enabled results.

**Brownfield** (an existing offering adopting 20x, often the more common case): point the read-only collectors at your existing account and let the pre-fill map the collected facts into a populated starting draft rather than a blank template. Three honest frictions apply: the metric history still starts accumulating only at adoption; an established account usually needs a remediation pass, because the collectors surface real drift honestly; and the governance-evidence indicators still require you to wire up the evidence location the Config custom rules check.

Either way the pipeline, the build gate, the drift check, and the trust boundary are identical — neither path shortcuts human verification or independent assessment.

## Describing your offering

Still in `profiles/common/offering-profile.json`, replace the placeholder identity fields: `organization_name`, `offering_name`, `offering_abbreviation`, `business_purpose`, `service_model`, `deployment_model`, `aws_partition`, `primary_region`, `dr_region`, `iac_technology`. These feed the metadata block that `SDR-CSO-MTD` requires.

Set `sdr_last_updated` when your content genuinely changes. It is manual on purpose: generated files carry no automatic timestamps, so that two builds of unchanged inputs stay byte-identical.

## Then what

Open `sdr/records/records-store.json`. It has 168 rule entries and 46 indicator entries, each pre-populated with `TBD` markers and inline guidance describing what the requirement is looking for.

Do not start at the top. Run the readiness scanner and let it order the work for you:

```bash
python automation/sdrscan/sdrscan.py --only-fails --severity critical,high
```

Every finding names the rule that makes it a requirement and the exact JSON path to fix. Work the critical findings first. The [implementation guide](implementation-guide.md) walks through a single entry end to end.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `ModuleNotFoundError: No module named 'jsonschema'` | Install the three prerequisites above. Note that `python-docx` imports as `docx`, which trips people up |
| The validator reports content fidelity mismatches | You hand-edited a generated file. Regenerate with `python sdr.py build`. The only file you edit is the record store |
| Word files differ between builds | Expected. The `.docx` container embeds file-entry timestamps, so bytes differ while content is identical. JSON, text, and CSV outputs are byte-stable, which is why the gate excludes `.docx` from its diff |
| Continuous integration fails on a stale check catalog | You changed `automation/sdrscan/checks.py` without regenerating the catalog. Run `python automation/sdrscan/sdrscan.py --write-catalog` |
| The drift check opened an issue | FedRAMP changed a pinned source. That is the system working. See [validation](validation.md#upstream-drift) |
| `Class D SDR generation is not supported` | Correct behavior. Class D is FedRAMP pending, so there is nothing to generate. Read `profiles/class-d-future/readiness-register.json` instead |
