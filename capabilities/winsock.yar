rule winsock
{
	meta:
		description = "Utilizes Winsock"
		reference = ""

	strings:
		$ = "WSAStartup" ascii wide
		$ = "ws2_32.dll" ascii wide nocase

	condition:
		any of them
}
