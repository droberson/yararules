rule mysterysnail
{
	meta:
		author = "Daniel Roberson"
		description = "MysterySnail RAT"
		reference = "https://securelist.com/mysterysnail-attacks-with-windows-zero-day/104509/"
		hash = "b7fb3623e31fb36fc3d3a4d99829e42910cad4da4fa7429a2d99a838e004366e"

	strings:
		$ = "IP:%d.%d.%d.%d"
		$ = "IP:error"
		$ = "CONNECT %s:%d HTTP/1.1"

	condition:
		uint16(0) == 0x5a4d and all of them
}
