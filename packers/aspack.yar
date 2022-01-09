import "pe"

rule aspack
{
	meta:
		description = "PE file packed with ASPack"

	condition:
		uint16(0) == 0x5a4d and
		for any i in (0..pe.number_of_sections - 1):
		(
			pe.sections[i].name == ".aspack"
		)
}
