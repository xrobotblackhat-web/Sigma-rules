rule RunHTMLApplication_Usage {
    meta:
        description = "Detects binary that imports or references RunHTMLApplication, often used with rundll32"
        severity = "high"
        attack.tactic = "TA0002"
        attack.technique = "T1218.011"
        attack.id = "T1218.011"
    strings:
        $a = "RunHTMLApplication" fullword ascii
        $b = "mshtml" fullword ascii
        $c = "javascript:" fullword ascii wide
        $d = "vbscript:" fullword ascii wide
        $e = "\..\mshtml" fullword ascii
    condition:
        ($a or $b) and (any of ($c,$d,$e))
}
