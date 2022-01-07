rule sevenzip
{
	meta:
		description = "7-zip file"

	condition:
		uint16(0) == 0x7a37
}
