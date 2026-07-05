rule Process_Enumeration {
    meta:
        description = "Detects APIs for process enumeration (e.g., CreateToolhelp32Snapshot)"
        severity = "low"
        attack.tactic = "TA0007"
        attack.technique = "T1057"
        attack.id = "T1057"
    strings:
        $a = "CreateToolhelp32Snapshot" fullword ascii
        $b = "Process32First" fullword ascii
        $c = "Process32Next" fullword ascii
        $d = "EnumProcesses" fullword ascii
    condition:
        any of them
}
