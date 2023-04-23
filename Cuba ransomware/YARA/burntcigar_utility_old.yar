rule burntcigar_utility_old {
 meta:
 description = "Rule to detect the old version of Burntcigar utility, often associated
to ransomware operations"
 author = "Kaspersky"
 copyright = "Kaspersky"
 version = "1.0"
 distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE
ON ANY THREAT INTEL PLATFORM"
 last_modified = "2022-07-06"
 hash1 = "c9d3b29e0b7662dafc6a1839ad54a6fb"
 hash1 = "9ca2579117916ded7ac8272b7b47bb98"
 strings:
 $x1 = "HostedAgent.exe" fullword wide
 $s2 = "SentinelServiceHost.exe" fullword wide
 $s3 = "SentinelAgent.exe" fullword wide
 $s4 = "SentinelAgentWorker.exe" fullword wide
 $s5 = "McsAgent.exe" fullword wide
 $s6 = "SEPAgent.exe" fullword wide
 $s7 = "ssDVAgent.exe" fullword wide
 $s8 = "svcGenericHost.exe" fullword wide
 $s9 = "logWriter.exe" fullword wide
 $s10 = "klnagent.exe" fullword wide
 $s11 = "SentinelHelperService.exe" fullword wide
 $s12 = "SAVAdminService.exe" fullword wide
 $s13 = "SavService.exe" fullword wide
 $s14 = "SEDService.exe" fullword wide
 $s15 = "SSPService.exe" fullword wide
 $s16 = "SophosNtpService.exe" fullword wide
 $s17 = "xmscoree.dll" fullword wide
 $s18 = "SentinelStaticEngineScanner.exe" fullword wide
 $s19 = "SophosFileScanner.exe" fullword wide
 $s20 = "scanhost.exe" fullword wide
 $op0 = { 0f 11 45 c0 eb 69 8b f7 b8 ff ff ff 7f 83 ce 0f }
 $op1 = { 68 34 59 43 00 8d 4d d8 c7 45 e8 }
 $op2 = { 83 d7 ff 01 4d 08 85 ff 0f 8f 71 ff ff ff 7c 08 }
 condition:
 ( uint16(0) == 0x5a4d and filesize < 700KB and ( 1 of ($x*) and 4 of them ) and all of
($op*)
 ) or ( all of them )
}
