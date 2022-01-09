rule clck_ru
{
	meta:
		description = "Contains 'clck.ru' string"

	strings:
		$ = "clck.ru" ascii wide nocase

	condition:
		all of them
}
