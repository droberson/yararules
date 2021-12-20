rule ngrok_url
{
	meta:
		description = "Contains ngrok.io string"

	strings:
		$ = ".ngrok.io" ascii wide

	condition:
		all of them
}
