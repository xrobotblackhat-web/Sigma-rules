rule IcedID_ExplorerCOM {
    meta:
        description = "Detects Explorer COM abuse (IcedID pattern)"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "Shell.Application" fullword ascii wide
        $b = "Explorer" fullword ascii wide
        $c = "DesktopAutomation" fullword ascii wide
    condition:
        $a and (any of ($b,$c))
}
