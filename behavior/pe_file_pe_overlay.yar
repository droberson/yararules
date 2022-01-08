import "pe"

rule pe_file_pe_overlay
{
	meta:
		description = "PE files containing a PE file in its overlay"
		reference = "https://twitter.com/greglesnewich/status/1479081818553040897"
		hash = "676334825526feb7aeb8975af9fd5568d0f93b6a9bfe45459e4530725277faab"
	condition:
		uint16(pe.overlay.offset) == 0x5a4d // MZ header at overlay offset
}

rule pe_file_pe_overlay_xor
{
	meta:
		description = "PE files containing an XOR'd PE header as an overlay"
		hash = "67d8ca9a198597bd0f9fb91ac64a859526c8ed0b6bdf793b9f8abc648e41e9af"
	strings:
		$mz = "MZ" xor

	condition:
		$mz at pe.overlay.offset
}
