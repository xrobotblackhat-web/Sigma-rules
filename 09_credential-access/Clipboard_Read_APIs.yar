rule Clipboard_Read_APIs {
    meta:
        description = "Detects clipboard read permissions and access (common for crypto wallet theft)"
        severity = "high"
        attack.tactic = "TA0006"
        attack.technique = "T1056"
        attack.id = "T1056"
    strings:
        $a = "clipboardRead" fullword ascii
        $b = "clipboard-write" fullword ascii
        $c = "navigator.clipboard.read" fullword ascii
        $d = "navigator.clipboard.readText" fullword ascii
    condition:
        any of them
}
