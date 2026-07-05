rule Service_Modification {
    meta:
        description = "Detects service modification (change binPath, start type) for persistence"
        severity = "medium"
        attack.tactic = "TA0003"
        attack.technique = "T1543"
        attack.id = "T1543"
    strings:
        $a = "sc.exe config" fullword ascii wide
        $b = "sc config" fullword ascii wide
    condition:
        any of them
}
