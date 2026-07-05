rule Extension_Eval_Usage {
    meta:
        description = "Detects use of eval, Function, or setTimeout with string in extension scripts (common for remote code)"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1059"
        attack.id = "T1059"
    strings:
        $eval = "eval(" fullword ascii
        $func = "new Function(" fullword ascii
        $timeout = "setTimeout("" fullword ascii
        $setinterval = "setInterval("" fullword ascii
        $blob = "new Blob([" fullword ascii
        $dataurl = "data:text/javascript" fullword ascii
    condition:
        any of them
}
