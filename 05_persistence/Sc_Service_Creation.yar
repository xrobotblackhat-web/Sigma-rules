rule Sc_Service_Creation {
    meta:
        description = "Detects use of sc.exe or CreateService APIs (service persistence)"
        severity = "high"
        attack.tactic = "TA0003"
        attack.technique = "T1543"
        attack.id = "T1543"
    strings:
        $a = "sc.exe create" fullword ascii wide
        $b = "sc create" fullword ascii wide
        $c = "CreateService" fullword ascii
        $d = "OpenSCManager" fullword ascii
    condition:
        any of them
}
