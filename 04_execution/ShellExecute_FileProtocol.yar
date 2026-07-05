rule ShellExecute_FileProtocol {
    meta:
        description = "Detects ShellExecute combined with file:// string (potential remote file execution)"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "ShellExecute" fullword ascii
        $b = "file://" fullword ascii wide
    condition:
        $a and $b
}
