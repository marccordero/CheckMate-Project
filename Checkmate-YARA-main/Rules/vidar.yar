rule vidar_wallets : Stealer {
    meta:
        Author = "Checkmate"
        Description = "Simple rule to detect vidar stealer looking for wallets"
        MD5 = "757a441a4eaad964c783c5b072586b38"

    strings:
        $lmao = "A caf? racer is a genre of sport motorcycles that originated among British motorcycle enthusiasts of the early 1960s in London" ascii // idk
        $tronium_wallet = "Tronium" ascii // Tronium wallet
        $Ext_1 = "gojhcdgcpbpfigcaejpfhfegekdgiblk" ascii // ? browser extension
        $opera_wallet = "Opera Wallet" ascii //Opera Wallet
        $trust_wallet = "Trust Wallet" ascii // Trust Wallet
        $Tron_Wallet_Ext = "pnndplcbkakcplkjnolgbkdgjikjednm" ascii // Tron Wallet Extension
        $exodus_wallet = "Exodus Web3 Wallet" ascii // Exodus Wallet
        $exodus_wallet2 = "Exodus.............." fullword ascii // Exodus Wallet Dir
        $exodus_backups = "Exodus........" fullword ascii // Exodus Wallet Backups
        $Trust_Wallet_Ext = "egjidjbpglichdcondbcbdnbeeppgdph" ascii // Trust Wallet Extension
        $braavos_wallet = "Braavos" ascii // Braavos Wallet
        $Exodus_Wallet_Ext = "aholpfdialjgjfhomihkjbmgjidlcdno" ascii // Exodus Wallet Extension
        $Enkrypt_wallet = "Enkrypt" ascii // Enkrypt Wallet
        $Braavos_Wallet_Ext = "jnlgamecbpmbajjfhmmmlhejkemejdma" ascii // Braavos Wallet Extension
        $OKX_Wallet = "OKX Web3 Wallet" ascii // OKX Wallet
        $Enkrypt_Ext = "kkpllkodjeloidieedojogacfhpaihoh" ascii // Enkrypt Wallet Extension
        $sender_wallet = "Sender" ascii // Sender Wallet
        $OKX_Wallet_Ext = "mcohilncbfahbmgdjkbpemcciiolgcge" ascii // OKX Wallet Extension
        $Hashpack_wallet = "Hashpack" ascii // Hashpack Wallet
        $Sender_Ext = "epapihdplajcdnnkdeiahlgigofloibg" ascii // Sender Wallet Extension
        $eternl_wallet = "Eternl" ascii // Eternl Wallet
        $Hashpack_Ext = "gjagmgiddbbciopjhllkdnddhcglnemk" ascii // Hashpack Wallet Extension
        $gero_wallet = "GeroWallet" ascii // Gero Wallet
        $Etnerl_Ext = "kmhcihpebfmpgmihbkipmjlmmioameka" ascii // Eternl Wallet Extension
        $Pontem_wallet = "Pontem Wallet" ascii // Pontem Wallet
        $Gero_Wallet_Ext = "bgpipimickeadkjlklgciifhnalhdjhe" ascii // Gero Wallet Extension
        $petra_wallet = "Petra Wallet" ascii // Petra Wallet
        $Pontem_Aptos_Wallet_Ext = "phkbamefinggmakgklpkljjmgibohnba" ascii // Pontem Wallet Extension
        $martian_wallet = "Martian Wallet" ascii // Martian Wallet
        $Petra_Aptos_Wallet_Ext = "ejjladinnckdgjemekebdpeokbikhfci" ascii // Petro Aptos Wallet Extension
        $Finnie_wallet = "Finnie" ascii // Finnie Wallet
        $Martian_Wallet_Ext = "efbglgofoippbgcjepnhiblaibcnclgk" ascii // Martian Wallet Extension
        $leap_terra_wallet = "Leap Terra" ascii // Leap Terra Wallet
        $Finnie_Ext = "cjmkndjhnagcfbpiemnkdpomccnjblmj" ascii // Finnie Wallet Extension
        $microsoft_fill = "Microsoft AutoFill" ascii // Microsoft Autofill Passwords
        $Microsoft_Password_Autofill_Ext = "fiedbfgcleddlbcmgdigjgdfcggjcion" ascii // Microsoft Autofill Passwords Extension
        $bitwarden = "Bitwarden" ascii // Bitwarden
        $Bitwarden_Ext = "nngceckbapebfimnlniiiahkandclblb" ascii // Bitwarden Extension
        $keepass = "KeePass Tusk" ascii // Keepass
        $keepassxc = "KeePassXC-Browser" ascii // Keepass
        $Keepass_tusk_Ext = "fmhmiaejopepamlcjkncpgpdjichnecm" ascii // Keepass Extension
        $keepass_xc_Ext = "oboonakemofpalcgghocfoadofidjkkk" ascii // Keepass Extension
        $possible_cc = "Card" ascii // Possible CC ?
        $c2 = "https://steamcommunity.com/profiles/76561199478503353" ascii // C2 server Allocated in Steam
        $telegram_c2 = "https://t.me/noktasina" ascii // C2 server allocated in Telegram
        $c2_ip = "http://95.217.152.87:80" ascii // C2 server
        
    condition:
        1 of ($*) // Execute all the strings
}
