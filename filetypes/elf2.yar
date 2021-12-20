rule elf_file_method2
{
	meta:
		description = "ELF file '\x7fELF' header as uint32"
		author = "Daniel Roberson"

	condition:
		uint32(0) == 0x464c457f
}
