import "pe"

rule ppid_spoofing
{
	meta:
		author = "Daniel Roberson"
		description = "Contains imports necessary to implement Parent Process ID (PPID) spoofing"

	condition:
		uint16(0) == 0x5a4d and
		pe.imports("kernel32.dll", "InitializeProcThreadAttributeList") and
		pe.imports("kernel32.dll", "OpenProcess") and
		pe.imports("kernel32.dll", "DuplicateHandle") and
		pe.imports("kernel32.dll", "UpdateProcThreadAttribute") and (pe.imports("kernel32.dll", "CreateProcessA") or pe.imports("kernel32.dll", "CreateProcessW"))
}
