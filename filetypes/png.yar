rule png
{
	meta:
		description = "PNG file"

	condition:
		uint32(0) == 0x474e5089
}
