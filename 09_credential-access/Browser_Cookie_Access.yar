rule Browser_Cookie_Access {
    meta:
        description = "Detects strings related to browser cookie theft (Chrome/Edge/Firefox)"
        severity = "high"
        attack.tactic = "TA0006"
        attack.technique = "T1539"
        attack.id = "T1539"
    strings:
        $a = "Cookies" fullword ascii wide
        $b = "Login Data" fullword ascii wide
        $c = "Local State" fullword ascii wide
        $d = "Web Data" fullword ascii wide
    condition:
        any of them
}
