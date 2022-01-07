rule zip_file
{
	meta:
		description = "Zip file"

	condition:
		uint16(0) == 0x4b50
}
