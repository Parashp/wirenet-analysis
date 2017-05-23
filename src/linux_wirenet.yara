import "elf"

rule linux_wirenet {

    meta:
        author = "shxdow"
        description = "Linux banking trojan"
        md5 = "9a0e765eecc5433af3dc726206ecc56e"
        sha1 = "5996d02c142588b6c1ed850e461845458bd94d17"
        
    strings:
        // $mozilla_db = "signons.sqlite"
        // $mozilla_cred = "login.json"
        // $sql_query = "select *"
        $elf_file = {7F 45 4C 46}
        $test_packet = "RGI28DQ30QB8Q1F"



    condition:
        // elf.machine == elf.EM_X86_64
        // $elf_file and $te
        all of them
}

