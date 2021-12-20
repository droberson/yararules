rule wwpack
{
	meta:
		description = "PE files packed with WWPACK"
		reference = "http://fileformats.archiveteam.org/wiki/WWPACK"

	strings:
		$wwp = "WWPACK"

	condition:
		uint16(0) == 0x5a4d and $wwp
}

rule wwpack_data
{
	meta:
		description = "Data files packed with WWPACK"
		reference = "http://fileformats.archiveteam.org/wiki/WWPACK"

	strings:
		$wwp = "WWP"

	condition:
		$wwp at 0
}
