rule wannacry {
    meta:
        Author = "Checkmate"
        Description = "Basic rule to identify WannaCry Ransomware"
        MD5 = "5c7fb0927db37372da25f270708103a2"

    strings:
        $c = "c.wry"  // Config
        $r = "r.wry"  // Ransom text
        $t = "t.wry" fullword ascii // Encrypted DLL
        $virtual_alloc = "VirtualAlloc" ascii // Very common technique
        $ext = ".doc" fullword wide
        $ext2 = ".docx" fullword wide 

    condition:
        $c or $r or $t or $virtual_alloc or $ext or $ext2
}