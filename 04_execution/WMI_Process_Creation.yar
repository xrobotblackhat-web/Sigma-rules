rule WMI_Process_Creation {
    meta:
        description = "Detects imports or strings related to WMI process creation (Win32_Process.Create)"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1047"
        attack.id = "T1047"
    strings:
        $a = "Win32_Process" fullword ascii
        $b = "IWbemLocator" fullword ascii
        $c = "IWbemServices" fullword ascii
        $d = "ExecMethod" fullword ascii
        $e = "Create" fullword ascii
        $f = "wbemprox" fullword ascii
        $g = "wbemcomn" fullword ascii
    condition:
        (1 of ($a,$b,$c,$d) and $e) or any of ($f,$g)
}
