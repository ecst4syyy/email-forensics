/*
  Example YARA rules for email-forensics (--yara examples/yara).
  Metadata used by the tool: severity = info|low|medium|high, description.
  These are illustrative starting points, not a curated threat-intel feed.
*/

rule PowerShell_EncodedCommand
{
    meta:
        description = "PowerShell started with an encoded command"
        severity = "high"
    strings:
        $ps = "powershell" nocase
        $enc = /-e(nc(odedcommand)?)?\s+[A-Za-z0-9+\/=]{40,}/ nocase
    condition:
        $ps and $enc
}

rule HTML_Smuggling_Blob
{
    meta:
        description = "Script that builds a downloadable file in the browser"
        severity = "high"
    strings:
        $blob = "new Blob(" nocase
        $url = "createObjectURL" nocase
        $dl = ".download" nocase
        $b64 = "atob(" nocase
    condition:
        $blob and $url and ($dl or $b64)
}

rule Office_AutoExec_Shell
{
    meta:
        description = "VBA auto-run macro text that starts a shell"
        severity = "high"
    strings:
        $a1 = "AutoOpen" nocase
        $a2 = "Document_Open" nocase
        $a3 = "Workbook_Open" nocase
        $s1 = "WScript.Shell" nocase
        $s2 = "Shell(" nocase
        $s3 = ".Run " nocase
    condition:
        any of ($a*) and any of ($s*)
}

rule Credential_Harvest_Form
{
    meta:
        description = "HTML form with a password field posting off-site"
        severity = "medium"
    strings:
        $form = /<form[^>]+action\s*=\s*["']?https?:\/\//i
        $pw = /type\s*=\s*["']?password/i
    condition:
        $form and $pw
}
