rule neshta
{
	meta:
		description = "Files impacted by Neshta virus"
		hash = "769e6e12a5443217fd8c5ce510846775b714eb221cc11974969b5ff7442b5484"

	strings:
		$ = "Delphi-the best. Fuck off all the rest. Neshta "
		$ = "Made in Belarus."

	condition:
		all of them
}
