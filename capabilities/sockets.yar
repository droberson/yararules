rule sockets
{
	meta:
		description = "Berkeley Sockets API"
		reference = "https://en.wikipedia.org/wiki/Berkeley_sockets"
		author = "Daniel Roberson"

	strings:
		$socket = "socket" fullword
		$ = "accept" fullword
		$ = "bind" fullword
		$ = "getsockname" fullword
		$ = "listen" fullword
		$ = "close" fullword

	condition:
		$socket and 2 of them
}
