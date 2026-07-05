rule Extension_Obfuscated_JS {
    meta:
        description = "Detects heavily obfuscated JavaScript (high entropy, long base64 strings)"
        severity = "medium"
        attack.tactic = "TA0005"
        attack.technique = "T1027"
        attack.id = "T1027"
    strings:
        $b64 = /[A-Za-z0-9+\/]{40,}={0,2}/  // long base64-like
        $hex = /[0-9a-fA-F]{40,}/            // long hex strings
        $concat = "['']" fullword ascii      // common obfuscation pattern
        $unescape = "unescape" fullword ascii
    condition:
        filesize > 5000 and ( (#b64 >= 3) or (#hex >= 3) or $concat or $unescape )
}
