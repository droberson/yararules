rule ezuri_packer
{
	meta:
		description = "ELF packed with ezuri crypter"
		reference = "https://github.com/guitmz/ezuri"

	strings:
		$ = "/stub/main.go"
		$ = "main.runFromMemory"

	condition:
		(uint32(0) == 0x464c457f or
		 uint32(0) == 0xfeedface or
         uint32(0) == 0xcefaedfe or
         uint32(0) == 0xfeedfacf or
         uint32(0) == 0xcffaedfe or
         uint32(0) == 0xcafebabe or
         uint32(0) == 0xbebafeca)
		 and all of them
}
