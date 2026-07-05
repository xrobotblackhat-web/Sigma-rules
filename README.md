# SigmaHQ Rules — Organized by MITRE ATT&CK Tactic

Source: https://github.com/SigmaHQ/sigma (full repo, all four rule folders)
Generated: 2026-05-05
Total unique rules: 3,731
Total copies in this archive: 6,043 (rules tagged with multiple tactics appear in each)

## Folder layout

Folders are prefixed with kill-chain order (01 → 15) so the listing sorts
naturally from reconnaissance to impact:

    01_reconnaissance/             26 rules
    02_resource-development/       39
    03_initial-access/            343
    04_execution/                1037
    05_persistence/               851
    06_privilege-escalation/      755
    07_defense-impairment/        408
    08_stealth/                  1085
    09_credential-access/         383
    10_discovery/                 262
    11_lateral-movement/          164
    12_collection/                126
    13_command-and-control/       306
    14_exfiltration/               90
    15_impact/                    166
    00_untagged/                    2

## Note on the SigmaHQ taxonomy

SigmaHQ has split MITRE's single "Defense Evasion" tactic into two:
  - defense-impairment — turning protections off (Defender tampering, log clearing, etc.)
  - stealth            — operating without being seen (obfuscation, masquerading, timestomping, etc.)

Combined, these cover what MITRE calls Defense Evasion (TA0005).

## Multi-tactic rules

Sigma rules can carry several `attack.<tactic>` tags. A rule mapped to both
"execution" and "command-and-control" appears in BOTH folders (same content,
same filename). This is intentional — it lets you browse a tactic folder and
see every relevant detection without missing cross-tagged ones.

## Manifest

`_manifest.csv` lists every unique rule with:
  - filename
  - title
  - severity level
  - all tactics it tags
  - all techniques it tags
  - which source SigmaHQ folder it came from (rules / rules-emerging-threats / rules-threat-hunting / rules-compliance)
  - original path within the SigmaHQ repo

Use this CSV to filter or pivot — e.g. open in Excel and filter by
`tactics contains "credential-access"` and `level = critical`.

## Source folders preserved

Each rule's source folder is recorded in the manifest:
  - rules/                     — main, validated detections (3,132)
  - rules-threat-hunting/      — broader, higher-FP hunting rules (139)
  - rules-emerging-threats/    — TA-, malware-, or CVE-specific (457)
  - rules-compliance/          — compliance-only (3)

## Convert any folder to your SIEM

```bash
# Logpoint
sigma convert -t logpoint -p logpoint_windows ./04_execution/

# Splunk
sigma convert -t splunk -p splunk_windows ./09_credential-access/

# Microsoft Sentinel / Defender
sigma convert -t microsoft365defender -p microsoft_xdr ./08_stealth/

# Elastic
sigma convert -t lucene -p ecs_windows ./03_initial-access/
```

## License

Detection Rule License (DRL) 1.1 — same as upstream SigmaHQ.
See https://github.com/SigmaHQ/Detection-Rule-License
