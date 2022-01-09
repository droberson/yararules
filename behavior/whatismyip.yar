rule whatismyip
{
	meta:
		description = "Contains 'whatismyip' string"
		hash1 = "a0e27e9c690f3635e024021f5a106807511a035380a4af4441adaeb45f4f3189"
		hash2 = "a0d07014832ce355f7199c418f16f8e00896c2eea3694bac3abad25863d19402"

	strings:
		$ = "whatismyip" ascii wide nocase

	condition:
		all of them
}
