rule pastebin
{
	meta:
		description = "Contains 'pastebin.com' string"

	strings:
		$ = "pastebin.com" ascii wide nocase

	condition:
		any of them
}
