rule python_reverse_shell
{
	meta:
		author = "Daniel Roberson"
		description = "python reverse shells"

	strings:
		$a = "python"
		$b = "socket"
		$c = "dup2"
		$d = "/bin/"

	condition:
		all of them
}

