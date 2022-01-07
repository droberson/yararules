rule rar_file
{
	meta:
		description = "RAR file"

	condition:
		uint32(0) == 0x21726152 // Rar!
}
