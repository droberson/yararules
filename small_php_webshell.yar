rule small_php_webshell
{
	meta:
		author = "Daniel Roberson"
		description = "Find small php webshells"

	strings:
		$a = "<?"
		$b = "?>"
		$c = "$_"

	condition:
		all of them and filesize < 100
}

