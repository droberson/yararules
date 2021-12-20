rule runkeys
{
	meta:
		description = "run key strings"

	strings:
		$ = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii nocase

	condition:
		any of them
}
