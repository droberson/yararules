rule loki2
{
	meta:
		author = "Daniel Roberson"
		description = "http://phrack.org/issues/51/6.html"

	strings:
		$a = "lokid: inactive client <%d> expired from list [%d]"
		$b = "[SUPER fatal] control should NEVER fall here"

	condition:
		any of them
}

