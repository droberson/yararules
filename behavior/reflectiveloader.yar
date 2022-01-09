rule reflectiveloader
{
	meta:
		description = "Find Reflective Loaders. Recommend further analysis."
		author = "Daniel Roberson"
		hash = "b5b2249413d21165cebf03c86e08d9b1e711e4e8617196e9c6f124a1632958fe"
		reference = "https://github.com/stephenfewer/ReflectiveDLLInjection"

	strings:
		$ = "ReflectiveLoader"

	condition:
		uint16(0) == 0x5a4d and all of them
}

rule reflectiveloader_string
{
	meta:
		description = "Contains 'ReflectiveLoader' string"

	strings:
		$ = "ReflectiveLoader" ascii wide nocase

	condition:
		all of them
}
