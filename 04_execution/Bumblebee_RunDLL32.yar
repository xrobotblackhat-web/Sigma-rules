rule Bumblebee_RunDLL32 {
    meta:
        description = "Detects rundll32 with specific arguments (Bumblebee loader)"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1218.011"
        attack.id = "T1218.011"
    strings:
        $a = "rundll32" fullword ascii wide
        $b = "shell32" fullword ascii wide
        $c = "#1" fullword ascii
    condition:
        $a and ($b or $c)
}
