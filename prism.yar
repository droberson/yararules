rule prism
{
	meta:
		author = "Daniel Roberson"
		description = "https://github.com/andreafabrizi/prism"

	strings:
		$a = "PRISM"
		$b = "I'm not root :("

	condition:
		any of them
}

