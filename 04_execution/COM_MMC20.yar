rule COM_MMC20 {
    meta:
        description = "Detects use of MMC20.Application COM object (abused for UAC bypass)"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1548"
        attack.id = "T1548"
    strings:
        $a = "MMC20.Application" fullword ascii wide
        $b = "Document.ActiveView" fullword ascii wide
    condition:
        any of them
}
