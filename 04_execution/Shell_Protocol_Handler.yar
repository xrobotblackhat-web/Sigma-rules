rule Shell_Protocol_Handler {
    meta:
        description = "Detects use of file://, shell:, search-ms: or similar protocol handlers in strings"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "file://" fullword ascii wide
        $b = "shell:" fullword ascii wide
        $c = "search-ms:" fullword ascii wide
        $d = "ms-settings:" fullword ascii wide
        $e = "FileProtocolHandlerA" fullword ascii
    condition:
        any of them
}
