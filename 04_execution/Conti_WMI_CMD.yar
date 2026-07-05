rule Conti_WMI_CMD {
    meta:
        description = "Detects WMI process creation followed by cmd (Conti operators pattern)"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1047"
        attack.id = "T1047"
    strings:
        $a = "winmgmt" fullword ascii
        $b = "cmd.exe /c" fullword ascii wide
    condition:
        $a and $b
}
