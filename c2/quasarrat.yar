rule quasar_rat
{
	meta:
		description = "Quasar RAT"
		reference = "https://github.com/quasar/Quasar"

	strings:
		$ = "GetKeyloggerLogsResponse"
		$ = "GetKeyloggerLogsDirectoryResponse"

	condition:
		uint16(0) == 0x5a4d and any of them
}
