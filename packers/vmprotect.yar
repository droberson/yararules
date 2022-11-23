import "pe"

rule vmprotect
{
	condition:
		pe.section_index(".vmp0") or pe.section_index(".vmp1")
}
