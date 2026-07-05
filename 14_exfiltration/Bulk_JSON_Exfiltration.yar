rule Bulk_JSON_Exfiltration {
    meta:
        description = "Detects stringifying large data and sending to external endpoint"
        severity = "high"
        attack.tactic = "TA0010"
        attack.technique = "T1048"
        attack.id = "T1048"
    strings:
        $a = "JSON.stringify" fullword ascii
        $b = "fetch(" fullword ascii
        $c = "chrome.cookies.getAll" fullword ascii
        $d = "localStorage" fullword ascii
    condition:
        ($a and $b) and (any of ($c,$d))
}
