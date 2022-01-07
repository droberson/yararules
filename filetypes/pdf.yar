rule pdf
{
	meta:
		description = "Find PDF files"

	condition:
		uint32(0) == 0x46445025 // %PDF
}
