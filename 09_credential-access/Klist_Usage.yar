rule Klist_Usage {
    meta:
        description = "Detects use of klist.exe (Kerberos ticket enumeration)"
        severity = "medium"
        attack.tactic = "TA0006"
        attack.technique = "T1558"
        attack.id = "T1558"
    strings:
        $a = "klist" fullword ascii wide
    condition:
        any of them
}
