rule Ad_Injection {
    meta:
        description = "Detects DOM injection of ads (iframe, banner, popup)"
        severity = "medium"
        attack.tactic = "TA0005"
        attack.technique = "T1564"
        attack.id = "T1564"
    strings:
        $a = "createElement('iframe')" fullword ascii
        $b = "createElement('div')" fullword ascii
        $c = "appendChild" fullword ascii
        $d = "style.display" fullword ascii
    condition:
        any of them
}
