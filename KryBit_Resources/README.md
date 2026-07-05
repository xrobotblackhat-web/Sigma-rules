# KryBit / 0APT Detection Pack – Sigma Rules

Generated on 2026-07-02 16:14:49

## Sigma Rules
All Sigma rules have been placed into the appropriate MITRE‑tactic folders:
- `03_initial-access`
- `04_execution` (not used in this pack)
- `05_persistence`
- `07_defense-impairment`
- `09_credential-access`
- `10_discovery`
- `11_lateral-movement`
- `12_collection`
- `14_exfiltration`
- `15_impact`

## Additional Resources
- **YARA rules** – in `KryBit_Resources/YARA/`
- **IOC feed** – `KryBit_Resources/IOC_Feed.csv` (placeholders, replace with real IOCs)
- **ATT&CK mapping** – `KryBit_Resources/ATTACK_Mapping.csv`
- This README

## Usage
1. Review the Sigma rules and adjust to your environment.
2. Convert them to your SIEM format using `sigma-cli`.
3. Incorporate YARA rules into your malware scanning.
4. Populate the IOC feed with real indicators.

## Tuning
Each Sigma rule includes `falsepositives` and `level` to guide tuning. Adjust thresholds and whitelists as needed.

## References
- FBI/CISA Medusa Advisory
- KryBit/0APT leak analysis
