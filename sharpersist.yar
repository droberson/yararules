rule sharpersist
{
	meta:
		author = "Daniel Roberson"
		description = "https://github.com/fireeye/SharPersist"

	strings:
		$a = "SharPersist"
		$b = "F935DC23-1CF0-11D0-ADB9-00C04FD58A0B"
		$c = "9d1b853e-58f1-4ba5-aefc-5c221ca30e48"

	condition:
		all of them
}

