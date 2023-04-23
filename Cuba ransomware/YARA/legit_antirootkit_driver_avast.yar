rule legit_antirootkit_driver_avast {
 meta:
 description = "Rule to detect the legit Avast anti-rootkit driver"
 author = "Kaspersky"
 copyright = "Kaspersky"
 version = "1.0"
 distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE
ON ANY THREAT INTEL PLATFORM"
 last_modified = "2022-07-06"
 hash1 = "a179c4093d05a3e1ee73f6ff07f994aa"
 strings:
 $c0 = {5f5b5dc3cccc48897424184889542410}
 $c1 = {555657415641574883ec20488b1d4f80}
 $c2 = {564883ec20488b1d867b02004885db74}
 $c3 = {534883ec30488b0d928e0200488d5424}
 $c4 = {531049894b08554883ec30f705c68002}
 $c5 = {5e0200488b05886202004c8b44245048}
 $c6 = {50393d2d4c02007448488b0d305b0200}
 $c7 = {5f02004d85c9745e488b05c662020048}
 $c8 = {542430498bcee807f5ffff4889050086}
 $c9 = {50488b05c35b02004885c074088b0089}
 $c10 = {50f705f1780200000400007456498bd7}
condition:
 uint16(0) == 0x5A4D and
 filesize < 900000 and
 10 of them
}
