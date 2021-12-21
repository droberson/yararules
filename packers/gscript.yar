rule gscript
{
	meta:
		author = "Daniel Roberson"
		description = "https://github.com/gen0cide/gscript"

	strings:
		$ = "github.com/gen0cide/gscript"

	condition:
		any of them
}

