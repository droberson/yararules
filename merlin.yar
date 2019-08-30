rule merlin
{
	meta:
		author = "Daniel Roberson"
		description = "https://github.com/Ne0nd0g/merlin"

	strings:
		$a = "github.com/Ne0nd0g/merlin/pkg/agent.(*Agent).Run"

	condition:
		any of them
}

