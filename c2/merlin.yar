rule merlin
{
	meta:
		author = "Daniel Roberson"
		description = "https://github.com/Ne0nd0g/merlin"

	strings:
		$a = "github.com/Ne0nd0g/merlin"

	condition:
		any of them
}

