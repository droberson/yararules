rule gscript
{
	meta:
		author = "Daniel Roberson"
		description = "https://github.com/gen0cide/gscript"

	strings:
		$a = "github.com/gen0cide/gscript/engine.New"

	condition:
		any of them
}

