rule suo_deserialization 
{
    strings:
        $header = { D0 CF 11 E0 A1 B1 1A E1 } 
        $s = "VsToolboxService" wide
        $a1 = "AAEAAAD"
        $a2 = "ew0KICAgICckdHl"
        $a3 = "yAoFZNmAU3l"
        $a4 = "kscDYs0KCcYAAAP"
        $a5 = "PFByb3BlcnR5R3J"
        $a6 = "PD94bWwgdm" 
    condition:
       $header at 0 and $s and any of ($a*)
}
