rule NtCreateUserProcess_Import {
    meta:
        description = "Detects import of NtCreateUserProcess (native API, often for evasion)"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "NtCreateUserProcess" fullword ascii
        $b = "ZwCreateUserProcess" fullword ascii
    condition:
        any of them
}
