rule pupy
{
	meta:
		author = "Daniel Roberson"
		description = "https://github.com/n1nj4sec/pupy"

	strings:
		$a = "pupy.error"
		$b = "get_pupy_config"

	condition:
		all of them
}

