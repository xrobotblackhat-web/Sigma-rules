rule Native_Syscall_Strings {
    meta:
        description = "Looks for string references to native API names, indicating dynamic resolution"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "NtCreateUserProcess" fullword ascii
        $b = "ZwCreateUserProcess" fullword ascii
        $c = "NtCreateThreadEx" fullword ascii
        $d = "ZwCreateThreadEx" fullword ascii
    condition:
        any of them
}
