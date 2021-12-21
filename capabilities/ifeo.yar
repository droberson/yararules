rule image_file_execution_options_registry_string
{
	meta:
		description = "IFEO registry string"

	strings:
		$ = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" ascii wide nocase

	condition:
		all of them
}
