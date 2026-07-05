rule RouteTheCall_API {
    meta:
        description = "Detects RouteTheCall import or zipfldr.dll reference (very rare)"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "RouteTheCall" fullword ascii
        $b = "zipfldr.dll" fullword ascii
        $c = "ZIPFLDR" fullword ascii
    condition:
        any of them
}
