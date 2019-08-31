rule upx
{
	meta:
		author = "Daniel Roberson"
		description = "https://github.com/upx/upx"

	strings:
		$a = { 7f 45 4c 46 }
		$b = "UPX!"

	condition:
		all of them
}

