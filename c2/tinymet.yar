rule tinymet
{
	meta:
		author = "Daniel Roberson"
		description = "https://github.com/SherifEldeeb/TinyMet"

	strings:
		$a = "tinymet.com"
		$b = "TinyMet"
		$c = "Available transports are as follows:"

	condition:
		all of them
}

