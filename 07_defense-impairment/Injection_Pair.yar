rule Injection_Pair {
    meta:
        description = "Detects both memory writing and remote thread creation – classic injection"
        severity = "critical"
        attack.tactic = "TA0005"
        attack.technique = "T1055"
        attack.id = "T1055"
    strings:
        $a = "WriteProcessMemory" fullword ascii
        $b = "CreateRemoteThread" fullword ascii
        $c = "VirtualAllocEx" fullword ascii
    condition:
        ($a and $b) or ($c and $b)
}
