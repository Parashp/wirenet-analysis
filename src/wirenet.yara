import "elf"

private rule wirenet_strings {

    meta:
        author = "shxdow"
        description = "Wirenet strings"

    strings:

        $test_packet = "RGI28DQ30QB8Q1F"
        $rc4_key = {55 B9 C7 D6 AC 4A 34 DF  C2 6A F4 E3 D8 C9 CC 42}
        $startup_config = "[Desktop Entry]\nType=Application.Exec=\"%s\"\nHidden=false\nName=%s"


        $firefox_db = "signons.sqlite"
        $new_ff_db = "login.json"
        $master_key = "key3.db"
        $thunderbird_path = "/.thunderbird/"
        $seamonkey = "/.mozilla/seamonkey/"

        // Windows paths

        // OSX paths

    
        $key1 = "[Caps Lock]"
        $key2 = "[Shift Lock]"
        $key3 = "[Arrow Left]"
        $key4 = "[Arrow Up]" 
        $key5 = "[Arrow Right]"
        $key6 = "[Arrow Down]"
        $key7 = "[Backspace]"
        $key8 = "[Delete]"
        $key9 = "[Num %s]"
        $key10 = "[Num Lock]"
        $key11 = "[Num Enter]"
        $key12 = "[F%d]"
        $key13 = "[Tab]"
        $key14 = "[Home]"
        $key15 = "[Page Up]"
        $key16 = "[Page Down]"
        $key17 = "[End]"
        $key18 = "[Begin]"
        $key19 = "[Break]"
        $key20 = "[Insert]"
        $key21 = "[Scroll Lock]"
        $key22 = "[Esc]"
        $key23 = "[Enter]"
        $key24 = "[Print Screen]"
        $key25 = "[Alt]"

    condition:
        // This rule is a big mess as:
        //      [*] wirenet specific strings should be optional
        //      [*] some of the firefox related things have to match
        //      [*] other mozilla / chrome products should be included
        //      [*]
        any of ($test_packet, $rc4_key, $startup_config) or any of ($firefox_db, $new_ff_db, $master_key) and (any of ( $thunderbird_path, $seamonkey ) or 7 of ( $key* ))
}

rule linux_wirenet {

    meta:
        author = "shxdow"
        description = "Cross-platform banking trojan"
        md5 = "9a0e765eecc5433af3dc726206ecc56e"
        sha1 = "5996d02c142588b6c1ed850e461845458bd94d17"

    condition:
        wirenet_strings and ( filesize < 100KB )
}
