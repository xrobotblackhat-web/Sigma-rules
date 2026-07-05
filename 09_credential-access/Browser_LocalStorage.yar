rule Browser_LocalStorage {
    meta:
        description = "Detects access to browser localStorage or sessionStorage via script"
        severity = "medium"
        attack.tactic = "TA0006"
        attack.technique = "T1539"
        attack.id = "T1539"
    strings:
        $a = "localStorage" fullword ascii
        $b = "sessionStorage" fullword ascii
        $c = "getItem" fullword ascii
    condition:
        any of them
}
