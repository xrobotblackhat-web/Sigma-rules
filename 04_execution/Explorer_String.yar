rule Explorer_String {
    meta:
        description = "Detects binary containing 'explorer.exe' (could be used for injection or persistence)"
        severity = "low"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "explorer.exe" fullword ascii wide
    condition:
        $a
}
