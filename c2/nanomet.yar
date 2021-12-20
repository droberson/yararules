rule nanomet
{
	meta:
		author = "Daniel Roberson"
		description = "https://github.com/kost/nanomet"

	strings:
		$a = "github.com/kost/nanomet"
		$b = "nanomet.exe"
		$c = "Available transports are as follows:"

	condition:
		all of them
}

