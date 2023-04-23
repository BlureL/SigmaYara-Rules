rule bat_utility_lower_defenses {
 meta:
 description = "Rule to detect the BAT utility used by some ransomware affiliates"
 author = "Kaspersky"
 copyright = "Kaspersky"
 version = "1.0"
 distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE
ON ANY THREAT INTEL PLATFORM"
 last_modified = "2022-07-06"
 hash1 = "5f9871f15aa65ca6f3c284c8d100dced"
 strings:
 $a0 = "REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\"
/v EnableLUA /t REG_DWORD /d 0 /f" fullword ascii
 $a1 = "rem install to reg" fullword ascii
 $a2 = "REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File
Execution Options\\HelpPane.exe\" /f /v Debugger /t REG_SZ /d
\"%windir%\\system32\\cmd.exe\"" fullword ascii
 $a3 = "rem create a exploitable directory" fullword ascii
 $a4 = "REG ADD \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal
Services\" /f /v fAllowUnsolicited /t REG_DWORD /d \"00000001\"" fullword ascii
 $a5 = "rem disable NLa" fullword ascii
 $a6 = "rem disable uac" fullword ascii
 $a7 = "REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File
Execution Options\\utilman.exe\" /f /v Debugger /t REG_SZ /d
\"%windir%\\system32\\cmd.exe\"" fullword ascii
 $a8 = "REG ADD \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal
Services\" /f /v UserAuthentication /t REG_DWORD /d \"00000000\"" fullword ascii
 $a9 = "REG ADD \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal
Server\\WinStations\\RDP-Tcp\" /f /v SecurityLayer /t REG_DWORD /d \"00000001\"" fullword
ascii
 $a10 = "REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File
Execution Options\\Magnify.exe\" /f /v Debugger /t REG_SZ /d
\"%windir%\\system32\\cmd.exe\"" fullword ascii
 $a11 = "rem new installer with exploit" fullword ascii
 $a12 = "REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File
Execution Options\\sethc.exe\" /f /v Debugger /t REG_SZ /d \"%windir%\\system32\\cmd.exe\""
fullword ascii
 $a13 = "REG ADD \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows
NT\\Terminal Services\" /f /v fDenyTSConnections /t REG_DWORD /d \"00000000\"" fullword
ascii
condition:
 filesize < 8000 and
 10 of them
}
