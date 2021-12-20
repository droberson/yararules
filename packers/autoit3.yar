rule autoit3
{
	meta:
		description = "AutoIt 3"
		reference = "https://www.autoitscript.com/site/"
		decompiler = "http://domoticx.com/autoit3-decompiler-exe2aut/"

	strings:
		$ = "AutoIt v3" wide

	condition:
		uint16(0) == 0x5a4d and all of them
}
