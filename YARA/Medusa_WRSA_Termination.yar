rule Medusa_WRSA_Termination {
    meta:
        description = "Detects taskkill targeting WRSA.exe (WebRoot SecureAnywhere) – seen in Medusa"
        severity = "high"
        attack.tactic = "TA0005"
        attack.technique = "T1562"
    strings:
        $a = "taskkill /im WRSA.exe" fullword ascii wide
        $b = "taskkill /im MsMpEng.exe" fullword ascii wide
        $c = "taskkill /im Sentinel" fullword ascii wide
    condition:
        any of them
}
