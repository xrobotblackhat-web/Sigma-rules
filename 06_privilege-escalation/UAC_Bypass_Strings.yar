rule UAC_Bypass_Strings {
    meta:
        description = "Detects strings associated with UAC bypass techniques"
        severity = "high"
        attack.tactic = "TA0004"
        attack.technique = "T1548"
        attack.id = "T1548"
    strings:
        $a = "fodhelper" fullword ascii
        $b = "sdclt" fullword ascii
        $c = "eventvwr" fullword ascii
        $d = "ms-settings" fullword ascii
        $e = "computerdefaults" fullword ascii
    condition:
        any of them
}
