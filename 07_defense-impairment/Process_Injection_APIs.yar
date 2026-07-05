rule Process_Injection_APIs {
    meta:
        description = "Detects common process injection API imports"
        severity = "high"
        attack.tactic = "TA0005"
        attack.technique = "T1055"
        attack.id = "T1055"
    strings:
        $a = "VirtualAllocEx" fullword ascii
        $b = "WriteProcessMemory" fullword ascii
        $c = "CreateRemoteThread" fullword ascii
        $d = "QueueUserAPC" fullword ascii
        $e = "NtCreateThreadEx" fullword ascii
        $f = "ZwCreateThreadEx" fullword ascii
        $g = "SetWindowsHookEx" fullword ascii
    condition:
        (3 or more of them)
}
