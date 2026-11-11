/*
   Watchtower AV default rule set. Add your own .yar files to
   %PROGRAMDATA%\WatchtowerAV\rules  — they are loaded automatically.
   meta.score: 0-100 contribution to the file's threat score.
*/

rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test file"
        score = 100
        family = "EICAR-Test-File"
    strings:
        $e = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $e at 0
}

rule Mimikatz_Strings
{
    meta:
        description = "Mimikatz credential dumping tool"
        score = 100
        family = "HackTool.Mimikatz"
    strings:
        $a = "sekurlsa::logonpasswords" ascii wide nocase
        $b = "gentilkiwi" ascii wide
        $c = "mimikatz" ascii wide nocase
        $d = "lsadump::" ascii wide nocase
    condition:
        2 of them
}

rule Ransomware_Note_Generic
{
    meta:
        description = "Text typical of ransomware notes / payloads"
        score = 60
        family = "Ransom.Generic"
    strings:
        $a = "your files have been encrypted" ascii wide nocase
        $b = "bitcoin" ascii wide nocase
        $c = "decrypt" ascii wide nocase
        $d = ".onion" ascii wide nocase
        $e = "private key" ascii wide nocase
    condition:
        $a and 2 of ($b, $c, $d, $e)
}

rule Ransomware_Recovery_Inhibit
{
    meta:
        description = "Binary embeds commands that destroy backups"
        score = 75
        family = "Ransom.Generic"
    strings:
        $a = "vssadmin delete shadows" ascii wide nocase
        $b = "wmic shadowcopy delete" ascii wide nocase
        $c = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $d = "wbadmin delete catalog" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 1 of them
}

rule CobaltStrike_Beacon_Strings
{
    meta:
        description = "Strings found in Cobalt Strike beacons"
        score = 90
        family = "Backdoor.CobaltStrike"
    strings:
        $a = "%s as %s\\%s: %d" ascii
        $b = "beacon.dll" ascii
        $c = "ReflectiveLoader" ascii
        $d = "%02d/%02d/%02d %02d:%02d:%02d" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Suspicious_PowerShell_InMemory
{
    meta:
        description = "PowerShell in-memory loader techniques"
        score = 50
        family = "Trojan.PSLoader"
    strings:
        $a = "System.Reflection.Assembly]::Load" ascii wide nocase
        $b = "VirtualAlloc" ascii wide nocase
        $c = "GetDelegateForFunctionPointer" ascii wide nocase
        $d = "FromBase64String" ascii wide nocase
    condition:
        3 of them
}

rule Office_Macro_AutoExec_Shell
{
    meta:
        description = "Macro auto-runs and launches a shell"
        score = 55
        family = "Trojan.MacroDropper"
    strings:
        $auto1 = "AutoOpen" ascii nocase
        $auto2 = "Document_Open" ascii nocase
        $auto3 = "Workbook_Open" ascii nocase
        $sh1 = "WScript.Shell" ascii nocase
        $sh2 = "Shell(" ascii nocase
        $sh3 = "powershell" ascii nocase
    condition:
        1 of ($auto*) and 1 of ($sh*)
}
