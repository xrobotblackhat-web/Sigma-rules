rule Net_User_Group {
    meta:
        description = "Detects use of net user / net group (user/group enumeration)"
        severity = "low"
        attack.tactic = "TA0007"
        attack.technique = "T1069"
        attack.id = "T1069"
    strings:
        $a = "net user" fullword ascii wide
        $b = "net group" fullword ascii wide
        $c = "net localgroup" fullword ascii wide
    condition:
        any of them
}
