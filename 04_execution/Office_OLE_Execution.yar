rule Office_OLE_Execution {
    meta:
        description = "Detects strings used by Office macros to launch processes"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1059.005"
        attack.id = "T1059.005"
    strings:
        $a = "Shell" fullword ascii
        $b = "CreateObject" fullword ascii
        $c = "WScript.Shell" fullword ascii
        $d = "Run" fullword ascii
        $e = "ThisWorkbook" fullword ascii
        $f = "AutoOpen" fullword ascii
        $g = "Document_Open" fullword ascii
    condition:
        (2 of ($a,$b,$c,$d) and ($e or $f or $g))
}
