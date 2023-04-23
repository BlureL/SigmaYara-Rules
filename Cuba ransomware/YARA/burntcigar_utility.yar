rule burntcigar_utility {
 meta:
 description = "Rule to detect the Burntcigar utility, often associated to ransomware"
 author = "Kaspersky"
 copyright = "Kaspersky"
 version = "1.0"
 distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE
ON ANY THREAT INTEL PLATFORM"
 last_modified = "2022-07-06"
 hash1 = "f2fa9a3ce883a7f5b43ba5c9ff7bdf75"
 strings:
 $a0 = "AQAPRQVH3" fullword ascii
 $a1 = "\\\\.\\aswSP_Avar" fullword ascii
 $a2 = "AXAX^YZAXAY" fullword ascii
 $a3 = "\\\\.\\aswSP_ArPot2" fullword ascii
condition:
 uint16(0) == 0x5A4D and
 filesize < 9000 and
 4 of them
}
