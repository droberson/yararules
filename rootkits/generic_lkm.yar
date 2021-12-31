import "elf"

rule rootkit_generic_linux_lkm
{
	meta:
		description = "Generic Linux LKM rootkit"

	strings:
		$lkm1 = "init_module"
		$lkm2 = "cleanup_module"
		$s1 = "get_syscall_table_bf"
		$s2 = "kallsyms_lookup_name"
		$s3 = "kallsyms_on_each_symbol"

	condition:
		uint32(0) == 0x464c457f and
		elf.type == elf.ET_REL and
		all of ($lkm*) and
		any of ($s*)
}
