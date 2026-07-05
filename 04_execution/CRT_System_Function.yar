rule CRT_System_Function {
    meta:
        description = "Detects import of C runtime 'system' function (often used for command execution)"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "system" fullword ascii
    condition:
        $a in (0..pe.size_of_image) and pe.is_dll == false
}
