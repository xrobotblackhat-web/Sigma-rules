rule Affiliate_Fraud {
    meta:
        description = "Detects injection of affiliate IDs into URLs (affiliate fraud)"
        severity = "medium"
        attack.tactic = "TA0005"
        attack.technique = "T1564"
        attack.id = "T1564"
    strings:
        $a = "?affid=" fullword ascii
        $b = "?ref=" fullword ascii
        $c = "?tag=" fullword ascii
        $d = "utm_source" fullword ascii
    condition:
        any of them
}
