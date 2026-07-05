rule RunDLL32_Combo {
    meta:
        description = "Detects strings that indicate rundll32 calling shell32 functions"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1218.011"
        attack.id = "T1218.011"
    strings:
        $a = "rundll32" fullword ascii wide
        $b = "shell32" fullword ascii wide
        $c = "Control_RunDLL" fullword ascii wide
    condition:
        $a and ($b or $c)
}
