rule pyinstaller
{
	meta:
		author = "Daniel Roberson"
		description = "https://www.pyinstaller.org/"

	strings:
		$a = "_MEIPASS"

	condition:
		all of them
}

