rule OpenURL_API {
    meta:
        description = "Detects import of OpenURL or related legacy IE functions"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "OpenURL" fullword ascii
        $b = "IEFRAME" fullword ascii
        $c = "URL.DLL" fullword ascii
        $d = "SHDOCVW" fullword ascii
        $e = "Navigate" fullword ascii
    condition:
        any of them
}
