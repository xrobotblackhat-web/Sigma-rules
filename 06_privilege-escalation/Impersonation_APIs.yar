rule Impersonation_APIs {
    meta:
        description = "Detects impersonation and logon APIs used for privilege elevation"
        severity = "high"
        attack.tactic = "TA0004"
        attack.technique = "T1134.001"
        attack.id = "T1134.001"
    strings:
        $a = "ImpersonateLoggedOnUser" fullword ascii
        $b = "ImpersonateSelf" fullword ascii
        $c = "RevertToSelf" fullword ascii
        $d = "SetThreadToken" fullword ascii
    condition:
        any of them
}
