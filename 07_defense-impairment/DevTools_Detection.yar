rule DevTools_Detection {
    meta:
        description = "Detects anti-debugging code that checks for developer tools"
        severity = "medium"
        attack.tactic = "TA0005"
        attack.technique = "T1497"
        attack.id = "T1497"
    strings:
        $a = "devtools" fullword ascii
        $b = "debugger" fullword ascii
        $c = "console.log" fullword ascii
        $d = "console.error" fullword ascii
        $e = "devtools.detected" fullword ascii
    condition:
        any of them
}
