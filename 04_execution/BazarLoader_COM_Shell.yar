rule BazarLoader_COM_Shell {
    meta:
        description = "Detects use of Shell.Application COM object and ShellExecute (BazarLoader common chain)"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "Shell.Application" fullword ascii wide
        $b = "ShellExecute" fullword ascii
    condition:
        $a and $b
}
