rule JWT_OAuth_Token_Access {
    meta:
        description = "Detects token extraction from localStorage / sessionStorage (JWT, OAuth)"
        severity = "high"
        attack.tactic = "TA0006"
        attack.technique = "T1539"
        attack.id = "T1539"
    strings:
        $a = "access_token" fullword ascii wide
        $b = "refresh_token" fullword ascii wide
        $c = "id_token" fullword ascii wide
        $d = "jwt" fullword ascii wide
        $e = "oauth" fullword ascii wide
    condition:
        any of them
}
