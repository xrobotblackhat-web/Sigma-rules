rule Win32_CreateProcess_API {
    meta:
        description = "Detects import of CreateProcess or variants"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "CreateProcessA" fullword ascii
        $b = "CreateProcessW" fullword ascii
        $c = "CreateProcessAsUserA" fullword ascii
        $d = "CreateProcessAsUserW" fullword ascii
        $e = "CreateProcessWithLogonW" fullword ascii
        $f = "CreateProcessWithTokenW" fullword ascii
    condition:
        any of them
}
