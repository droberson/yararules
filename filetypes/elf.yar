rule filetype_elf
{
	meta:
		description = "ELF file"
		author = "Daniel Roberson"

	condition:
		uint32(0) == 0x464c457f
}

rule elf_with_overlay
{
  meta:
    description = "Detects ELF binaries with appended data (overlay)"
    author = "Daniel Roberson"

  condition:
    uint32(0) == 0x464c457f and
    (
      (
        uint8(0x04) == 2 and  // ELFCLASS64
        (
          (uint32(0x28) + (uint32(0x2C) << 32)) +  // e_shoff
          (uint16(0x3A) * uint16(0x3C))            // e_shnum * e_shentsize
        ) < filesize
      )
      or
      (
        uint8(0x04) == 1 and  // ELFCLASS32
        (
          uint32(0x20) +                // e_shoff
          (uint16(0x30) * uint16(0x2E)) // e_shnum * e_shentsize
        ) < filesize
      )
    )
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
