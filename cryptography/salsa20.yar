rule salsa20_constants
{
	meta:
		description = "Salsa20 stream cipher constants. Used by various ransomware"
		reference = "https://github.com/alexwebr/salsa20/blob/master/salsa20.c#L118-L125"

	strings:
		$ = "expand 32-byte k"

	condition:
		all of them
}
