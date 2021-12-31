rule lzexe
{
	meta:
		description = "PE file packed with LZEXE"

	strings:
		$s1 = "LZ09"
		$s2 = "LZ91"

	condition:
		uint16(0) == 0x5a4d and ($s1 at 28 or $s2 at 28)
}
