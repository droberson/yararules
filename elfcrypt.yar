rule elfcrypt
{
	meta:
		author = "Daniel Roberson"
		description = "http://github.com/droberson/ELFcrypt"

	strings:
		$a = "ELFcrypt by @dmfroberson"
		$b = "ELFcrypt2 by @dmfroberson"

	condition:
		any of them
}

