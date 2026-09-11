# Certification Package

FedRAMP 20x `FRC-CSO-PKG` defines the initial Certification Package as more than the Security Decision Record (SDR). This directory records the whole package boundary and states plainly which artifacts the framework generates today and which are planned, so no reader mistakes the SDR output for a complete package.

See [certification-package-manifest.json](certification-package-manifest.json) for the machine-readable version.

## What the initial package requires

| Artifact | CR26 rules | Required | This repository |
|---|---|---|---|
| Certification Package Overview (CPO) | `FRC-CSO-PKG`, `CPO-CSO-OVR` | Yes | Planned. The SDR references a CPO URI but the CPO itself is not yet generated. |
| Security Decision Record (SDR) | `SDR-CSO-FRR`, `SDR-CSX-KSI`, `SDR-CSX-KMT` | Yes | Implemented. JSON plus human-readable, with required semantic items carried and validated. |
| Ongoing Certification Report (OCR) | `FRC-CSO-PKG`, `CCM-OCR-AVL` | Yes, and every 3 months | Planned. |
| Secure Configuration Guide (SCG) | `SCG-CSO-RSC`, `SCG-CSO-AUP` | Class B and C | Planned. |
| Certification data sharing | `CDS-CSO-*` | Yes | Partial. Paired JSON and human-readable outputs support `CDS-CSO-CBF`; a trust center (`CDS-CSO-UTC`) and Class C availability service (`CDS-CSO-AVR`) are not implemented. |

## Scope honesty

This repository is a Security Decision Record framework today, not a complete Certification Package generator. The SDR is the deepest and most complete artifact; the CPO, OCR, and SCG are named here with their governing rules so the expansion path is explicit rather than implied.

Nothing in this directory is a compliance claim. A public GitHub Pages site is not a FedRAMP-compatible trust center, OSCAL is an interoperability export and not a native 20x submission format, and every generated artifact remains an unverified draft until a qualified human confirms it. See the caution banner in the top-level [README](../README.md).
