rule pedump_output
{
	meta:
		description = "output from 'pedump' ruby utility"

	strings:
		$ = "\n=== MZ Header ===\n"
		$ = "\n=== DOS STUB ===\n"
		$ = "\n=== RICH Header ===\n"
		$ = "\n=== PE Header ===\n"
		$ = "\n=== DATA DIRECTORY ===\n"
		$ = "\n=== SECTIONS ===\n"
		$ = "\n=== RESOURCES ===\n"
		$ = "\n=== IMPORTS ===\n"
		$ = "\n=== VERSION INFO ===\n"
		$ = "\n=== Packer / Compiler ===\n"

	condition:
		any of them
}
