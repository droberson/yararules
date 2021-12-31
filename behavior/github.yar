rule github
{
	meta:
		description = "Contains 'github.com' string"

	strings:
		$ = "github.com" ascii wide nocase

	condition:
		all of them
}
