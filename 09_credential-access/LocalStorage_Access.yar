rule LocalStorage_Access {
    meta:
        description = "Detects access to localStorage/sessionStorage (often to steal tokens)"
        severity = "medium"
        attack.tactic = "TA0006"
        attack.technique = "T1539"
        attack.id = "T1539"
    strings:
        $a = "localStorage" fullword ascii
        $b = "sessionStorage" fullword ascii
        $c = "getItem" fullword ascii
        $d = "setItem" fullword ascii
    condition:
        (any of ($a,$b)) and $c
}
