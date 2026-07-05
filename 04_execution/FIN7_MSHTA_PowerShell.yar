rule FIN7_MSHTA_PowerShell {
    meta:
        description = "Detects mshta.exe with PowerShell invocation (FIN7 style)"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1218.011"
        attack.id = "T1218.011"
    strings:
        $a = "mshta" fullword ascii wide
        $b = "powershell" fullword ascii wide
        $c = "javascript:" fullword ascii wide
    condition:
        $a and ($b or $c)
}
