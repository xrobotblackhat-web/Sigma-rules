rule Search_Hijack {
    meta:
        description = "Detects search engine manipulation (hijacking search queries)"
        severity = "high"
        attack.tactic = "TA0005"
        attack.technique = "T1564"
        attack.id = "T1564"
    strings:
        $a = "searchEngine" fullword ascii
        $b = "setDefaultSearchProvider" fullword ascii
        $c = "newTab" fullword ascii
        $d = "homepage" fullword ascii
    condition:
        any of them
}
