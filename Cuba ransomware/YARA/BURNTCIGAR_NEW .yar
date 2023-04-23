rule BURNTCIGAR_NEW 
{ 


  meta:
        author = "Kaspersky"
        description = "Rule to detect the new samples of BURNTCIGAR"
	copyright = "Kaspersky"
	strings:
		$hex1 = {8B 44 24 30} 
		$hex2 = {8B 45 A8} 
		$hex3 = {48 8D 15 AF FA 22 00}
		$hex4 = {68 00 EA 5D 00}
		$hex5 = {4D 46 43 41 70 70 6C 69 63 61 74 69 6F 6E}
		$a0 = "DeviceIoControl" fullword ascii
		$a1 = "Process32FirstW" fullword ascii
		$a2 = "Process32NextW" fullword ascii
    $a3 = "SetWindowsHookExW" fullword ascii

	condition:
		uint16(0) == 0x5A4D and
		filesize < 6000KB and
		($hex1 or $hex2) and
		($hex3 or $hex4) and $hex5 and 
    all of ($a*)

}
