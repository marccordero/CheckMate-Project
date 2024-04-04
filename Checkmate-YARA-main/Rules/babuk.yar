rule babuk {
    meta:
        Author = "Checkmate"
        Description = "Yara rule to detect babuk samples"
    
    strings:
        $mutex = "DoYouWantToHaveSexWithCuongDong" 
        $ext = ".babyk" fullword wide 
        $admin = "ADMIN$" fullword wide 
        $shadow = "/c vssadmin.exe delete shadows /all /quiet" fullword wide 

    condition:
        $mutex or $ext or $admin or $shadow
}