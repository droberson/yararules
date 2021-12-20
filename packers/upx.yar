rule upx
{
	meta:
		author = "Daniel Roberson"
		description = "https://github.com/upx/upx"

	strings:
		$s1 = "UPX!"
		$s2 = "UPX executable packer"

	condition:
		(uint32(0) == 0x464c457f or uint16(0) == 0x5a4d) and all of them
}

