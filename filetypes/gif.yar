rule gif
{
	meta:
		description = "GIF file"

	condition:
		uint32(0) == 0x38464947
}
