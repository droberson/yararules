rule google_drive
{
	meta:
		description = "Contains 'drive.google.com' string"

	strings:
		$ = "drive.google.com" ascii wide nocase

	condition:
		all of them
}
