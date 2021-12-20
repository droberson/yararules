import "elf"

rule elf_file_method3
{
	meta:
		description = "ELF file with 'elf' module"
		author = "Daniel Roberson"

	condition:
		elf.type
}
