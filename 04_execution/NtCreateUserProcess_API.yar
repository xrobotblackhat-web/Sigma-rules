rule NtCreateUserProcess_API {
    meta:
        description = "Detects import of NtCreateUserProcess or ZwCreateUserProcess (native syscall stubs)"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "NtCreateUserProcess" fullword ascii
        $b = "ZwCreateUserProcess" fullword ascii
    condition:
        any of them
}
