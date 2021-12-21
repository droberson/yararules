rule ptrace
{
	meta:
		description = "ELF files possibly abusing ptrace"

	strings:
		$ = "ptrace"

	condition:
		uint32(0) == 0x464c457f and all of them
}
