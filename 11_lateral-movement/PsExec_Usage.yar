rule PsExec_Usage {
    meta:
        description = "Detects use of PsExec (remote execution, lateral movement)"
        severity = "critical"
        attack.tactic = "TA0008"
        attack.technique = "T1570"
        attack.id = "T1570"
    strings:
        $a = "PsExec.exe" fullword ascii wide
        $b = "psexec" fullword ascii wide
    condition:
        any of them
}
