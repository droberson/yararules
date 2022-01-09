rule bitly
{
	strings:
		$ = "bit.ly" ascii wide nocase

	condition:
		all of them
}
