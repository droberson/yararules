rule ppid_spoofing_broad
{
	meta:
		description = "Contains imports necessary to implement Parent Process ID (PPID) spoofing"

	strings:
		$ = "InitializeProcThreadAttributeList" wide ascii
		$ = "OpenProcess" wide ascii
		$ = "DuplicateHandle" wide ascii
		$ = "UpdateProcThreadAttribute" wide ascii
		$ = "CreateProcess" wide ascii

	condition:
		all of them
}
