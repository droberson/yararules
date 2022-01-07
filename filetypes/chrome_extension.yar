rule chrome_extension
{
	meta:
		description = "Google Chrome Extension"

	condition:
		uint32(0) == 0x34327243 // Cr24
}
