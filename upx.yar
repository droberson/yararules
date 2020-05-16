rule upx
{
	meta:
		author = "Daniel Roberson"
		description = "https://github.com/upx/upx"

	strings:
		$b = "UPX!"
		$c = "UPX executable packer"

	condition:
		uint32(0) == 0x464c457f
		or uint16(0) == 0x4d5a
		and all of them
}

