rule Extension_Dynamic_Import {
    meta:
        description = "Detects dynamic import() or WebAssembly instantiation (payload delivery)"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1059"
        attack.id = "T1059"
    strings:
        $import = "import(" fullword ascii
        $wasm = "WebAssembly.instantiate" fullword ascii
        $worker = "new Worker(" fullword ascii
    condition:
        any of them
}
