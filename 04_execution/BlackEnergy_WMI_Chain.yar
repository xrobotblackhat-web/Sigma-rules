rule BlackEnergy_WMI_Chain {
    meta:
        description = "Detects strings that indicate WMI followed by cmd/powershell (BlackEnergy pattern)"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1047"
        attack.id = "T1047"
    strings:
        $a = "wmic process call create" fullword ascii wide
        $b = "powershell -c" fullword ascii wide
        $c = "cmd.exe /c" fullword ascii wide
    condition:
        $a and (any of ($b,$c))
}
