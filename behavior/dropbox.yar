rule dropbox_url
{
	meta:
		description = "Contains a DropBox URL"

	strings:
		$ = "https://dl.dropbox.com/" ascii wide

	condition:
		all of them
}

rule dropbox
{
	meta:
		description = "Contains dropbox.com"

	strings:
		$ = "dropbox.com" ascii wide

	condition:
		all of them
}
