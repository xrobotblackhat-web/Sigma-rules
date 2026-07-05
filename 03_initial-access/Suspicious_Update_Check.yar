rule Suspicious_Update_Check {
    meta:
        description = "Detects dynamic update check via external domains (supply chain risk)"
        severity = "medium"
        attack.tactic = "TA0001"
        attack.technique = "T1195"
        attack.id = "T1195"
    strings:
        $a = "chrome.runtime.requestUpdateCheck" fullword ascii
        $b = "fetch('https://" fullword ascii
        $c = "update.json" fullword ascii
        $d = "/manifest.json" fullword ascii
    condition:
        $a and ($b or $c or $d)
}
