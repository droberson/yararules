rule filetype_elf
{
	meta:
		description = "ELF file"
		author = "Daniel Roberson"

	condition:
		uint32(0) == 0x464c457f
}


/* Other ways to do this
import "elf"

rule elf_file_method3
{
	meta:
		description = "ELF file with 'elf' module"
		author = "Daniel Roberson"

	condition:
		elf.type
}
rule elf_file_method1
{
	meta:
		description = "ELF file '\x7fELF' header as string"
		author = "Daniel Roberson"

	strings:
		$elf = "\x7fELF"

	condition:
		$elf at 0
}
*/
