rule COM_Object_Creation {
    meta:
        description = "Detects CreateObject calls for COM objects often abused"
        severity = "medium"
        attack.tactic = "TA0002"
        attack.technique = "T1106"
        attack.id = "T1106"
    strings:
        $a = "CreateObject(\"Shell.Application\")" fullword ascii wide
        $b = "CreateObject(\"WScript.Shell\")" fullword ascii wide
        $c = "CreateObject(\"Scripting.FileSystemObject\")" fullword ascii wide
        $d = "CreateObject(\"Excel.Application\")" fullword ascii wide
        $e = "CreateObject(\"Word.Application\")" fullword ascii wide
    condition:
        any of them
}
