import "pe"

rule pecompact
{
	strings:
		$ = "PECompact"

	condition:
		uint16(0) == 0x5a4d and
		for any i in (0..pe.number_of_sections - 1):
		(
				pe.sections[i].name == ".text" and
				pe.sections[i].characteristics & pe.SECTION_MEM_WRITE
		) and
		all of them
}

rule pecompact_section_names
{
	meta:
		description = "PE file packed with PECompact"

	strings:
		$ = "PECompact"

	condition:
		uint16(0) == 0x5a4d and
		for any i in (0..pe.number_of_sections - 1):
		(
				pe.sections[i].name == ".text" and
				pe.sections[i].characteristics & pe.SECTION_MEM_WRITE
		) and
		all of them
}

rule pecompact_string
{
	meta:
		description = "PE file containing 'PEcompact' string"
		hash = "677645bcf4fe63d9f028e4b17006c967e4c56e0fde56486b58de58d41eb19da7"

	strings:
		$ = "PECompact"

	condition:
		uint16(0) == 0x5a4d and all of them
}

