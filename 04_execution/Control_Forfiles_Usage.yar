rule Control_Forfiles_Usage {
    meta:
        description = "Detects use of control.exe or forfiles.exe (abused for execution)"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1218"
        attack.id = "T1218"
    strings:
        $a = "control.exe" fullword ascii wide
        $b = "forfiles.exe" fullword ascii wide
    condition:
        any of them
}
