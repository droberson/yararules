rule cab
{
	meta:
		description = "Microsoft CAB file"

	condition:
		uint32(0) == 0x4643534d
}
