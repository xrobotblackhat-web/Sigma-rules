rule TokenBased_CreateProcess {
    meta:
        description = "Detects imports for process creation with alternate tokens"
        severity = "high"
        attack.tactic = "TA0004"
        attack.technique = "T1134.002"
        attack.id = "T1134.002"
    strings:
        $a = "CreateProcessAsUserA" fullword ascii
        $b = "CreateProcessAsUserW" fullword ascii
        $c = "CreateProcessWithLogonW" fullword ascii
        $d = "CreateProcessWithTokenW" fullword ascii
        $e = "DuplicateTokenEx" fullword ascii
    condition:
        any of ($a,$b,$c,$d) and $e
}
