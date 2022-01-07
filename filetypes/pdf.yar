rule pdf
{
	meta:
		description = "PDF file"

	condition:
		uint32(0) == 0x46445025 // %PDF
}
