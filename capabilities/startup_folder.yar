rule windows_startup_folder
{
	meta:
		description = "Windows Startup Folder strings"

	strings:
		$ = "Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii wide nocase

	condition:
		any of them
}
