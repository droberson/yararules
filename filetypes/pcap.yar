rule pcap_file
{
	meta:
		description = "Packet capture (pcap) files"

	condition:
		uint32(0) == 0xa1b2c3d4 or uint32(0) == 0xa1b23c4d or
		uint32be(0) == 0xa1b2c3d4 or uint32be(0) == 0xa1b23c4d
}
