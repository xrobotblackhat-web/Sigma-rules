rule Office_Macro_Strings {
    meta:
        description = "Detects VBA macro strings that invoke Shell or CreateObject"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1059.005"
        attack.id = "T1059.005"
    strings:
        $a = "Shell " fullword ascii wide
        $b = "CreateObject(" fullword ascii wide
        $c = "WScript.Shell" fullword ascii wide
        $d = "ThisDocument" fullword ascii wide
    condition:
        ($a or $b) and $d
}
