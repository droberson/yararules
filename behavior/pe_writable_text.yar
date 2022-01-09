import "pe"

rule pe_writable_text
{
	condition:
		uint16(0) == 0x5a4d and
		for any i in (0..pe.number_of_sections - 1):
		(
				pe.sections[i].name == ".text" and
				pe.sections[i].characteristics & pe.SECTION_MEM_WRITE
		)
}
