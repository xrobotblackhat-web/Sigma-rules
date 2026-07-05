rule Obfuscated_JS_VBS {
    meta:
        description = "Detects obfuscated JavaScript/VBScript patterns (eval, unescape, etc.)"
        severity = "medium"
        attack.tactic = "TA0005"
        attack.technique = "T1027"
        attack.id = "T1027"
    strings:
        $a = "eval(" fullword ascii
        $b = "unescape(" fullword ascii
        $c = "fromCharCode" fullword ascii
        $d = "atob(" fullword ascii
    condition:
        any of them
}
