rule Icacls_Takeown {
    meta:
        description = "Detects use of icacls.exe or takeown.exe (permission changes, often for privilege)"
        severity = "medium"
        attack.tactic = "TA0005"
        attack.technique = "T1222"
        attack.id = "T1222"
    strings:
        $a = "icacls" fullword ascii wide
        $b = "takeown" fullword ascii wide
    condition:
        any of them
}
