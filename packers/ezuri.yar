rule ezuri_packer
{
	meta:
		description = "ELF packed with ezuri crypter"
		reference = "https://github.com/guitmz/ezuri"

	strings:
		$ = "/stub/main.go"
		$ = "main.runFromMemory"

	condition:
		uint32(0) == 0x464c457f and all of them
}
