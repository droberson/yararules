rule upx
{
	meta:
		author = "Daniel Roberson"
		description = "https://github.com/upx/upx"

	strings:
		$elf = { 7f 45 4c 46 }
		$pe = { 4d 5a }

		$s1 = "UPX!"
		$s2 = "UPX executable packer"

	condition:
		($elf or $pe) and any of ($s*)
}

