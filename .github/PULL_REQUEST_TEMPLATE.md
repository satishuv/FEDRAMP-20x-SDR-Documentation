# Pull request

## What this changes

<!-- One or two sentences. What is different after this merges. -->

## Why

<!-- The problem, not the patch. Link the issue if there is one: Closes #123 -->

## If this touches a FedRAMP requirement

Delete this section if it does not. Otherwise fill it in completely; a pull request that changes how a requirement is read and does not cite the requirement will be asked to.

| | |
|---|---|
| Identifier | <!-- FRC-CSX-VVK --> |
| Dataset path | <!-- FRR / FRC / data / 20x / CSX / FRC-CSX-VVK --> |
| Class scope | <!-- all classes, or which ones if it has a varies_by_class object --> |

Statement, quoted from `references/fedramp-consolidated-rules.json`:

```text

```

Why that statement requires this change:

<!-- Argue from the quoted text. Cite the FRD definition too if your reading depends on one. -->

## Verification

Paste the tail of your run. Reviewers look for `hard failures: 0`.

```text
$ python sdr.py all

```

- [ ] `hard failures: 0`
- [ ] `content_fidelity_against_dataset` passes, which is the proof no generated file was hand-edited
- [ ] Regeneration is clean: `python sdr.py build` then `git diff` shows nothing outside `.docx`
- [ ] If `automation/sdrscan/checks.py` changed, the catalog was regenerated with `--write-catalog`

## Hygiene

- [ ] No account identifiers, credentials, endpoints, customer names, or restricted report content anywhere in the diff, including tests and fixtures
- [ ] No new runtime dependency, or the reason for one is stated below
- [ ] No status reaches `Implemented` without a deterministic check plus a named human
- [ ] No em dashes or en dashes in prose or commit messages
- [ ] Files stay LF, which the determinism contract in `.gitattributes` requires

## Anything a reviewer should push back on

<!-- Where you are unsure, what you left out, what you would do differently with more time.
     This section makes review faster, not weaker. -->
