rule PrintSpooler_String {
    meta:
        description = "Detects Print Spooler component strings (abused by Stuxnet and others)"
        severity = "medium"
        attack.tactic = "TA0003"
        attack.technique = "T1543"
        attack.id = "T1543"
    strings:
        $a = "spoolsv.exe" fullword ascii wide
        $b = "Print Spooler" fullword ascii wide
        $c = "\\.\spool" fullword ascii wide
    condition:
        any of them
}
