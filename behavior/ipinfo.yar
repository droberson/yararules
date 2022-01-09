rule ipinfo_io
{
	meta:
		description = "Contains 'ipinfo.io' string"

	strings:
		$ = "ipinfo.io" ascii wide nocase

	condition:
		all of them
}
