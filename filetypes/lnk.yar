rule lnk_file
{
	meta:
		description = "LNK file"

	strings:
		$lnk_magic = { 4c 00 }
		$lnk_clsid = { 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }

	condition:
		$lnk_magic at 0 and $lnk_clsid at 4
}

rule lnk_file_rundll32
{
	meta:
		description = "LNK file containing 'rundll32' string"

	strings:
		$lnk_magic = { 4c 00 }
		$lnk_clsid = { 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
		$rundll = "rundll32" ascii wide nocase

	condition:
		$lnk_magic at 0 and $lnk_clsid at 4 and $rundll
}

rule lnk_file_cmd
{
	meta:
		description = "LNK file with 'cmd.exe' string"

	strings:
		$lnk_magic = { 4c 00 }
		$lnk_clsid = { 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
		$cmd = "cmd.exe" ascii wide nocase

	condition:
		$lnk_magic at 0 and $lnk_clsid at 4 and $cmd
}

rule lnk_file_powershell
{
	meta:
		description = "LNK file with 'powershell' string"

	strings:
		$lnk_magic = { 4c 00 }
		$lnk_clsid = { 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
		$powershell = "powershell" ascii wide nocase

	condition:
		$lnk_magic at 0 and $lnk_clsid at 4 and $powershell
}

rule lnk_file_cscript
{
	meta:
		description = "LNK file with 'cscript' string"

	strings:
		$lnk_magic = { 4c 00 }
		$lnk_clsid = { 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
		$cscript = "cscript" ascii wide nocase

	condition:
		$lnk_magic at 0 and $lnk_clsid at 4 and $cscript
}

rule lnk_file_wscript
{
	meta:
		description = "LNK file with 'wscript' string"

	strings:
		$lnk_magic = { 4c 00 }
		$lnk_clsid = { 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
		$wscript = "wscript" ascii wide nocase

	condition:
		$lnk_magic at 0 and $lnk_clsid at 4 $wscript
}
