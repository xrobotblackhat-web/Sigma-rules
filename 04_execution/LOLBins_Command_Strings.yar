rule LOLBins_Command_Strings {
    meta:
        description = "Looks for embedded command lines using LOLBins in strings"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1218"
        attack.id = "T1218"
    strings:
        $a = "cmd.exe /c" fullword ascii wide
        $b = "powershell -" fullword ascii wide
        $c = "wscript" fullword ascii wide
        $d = "cscript" fullword ascii wide
        $e = "mshta" fullword ascii wide
        $f = "rundll32" fullword ascii wide
        $g = "regsvr32 /s" fullword ascii wide
        $h = "msbuild" fullword ascii wide
        $i = "installutil" fullword ascii wide
        $j = "csc.exe" fullword ascii wide
    condition:
        any of them
}
