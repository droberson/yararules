rule sliver_client
{
	meta:
		description = "Bishop Fox's Sliver C2 Implant"
		author = "Daniel Roberson"
		url = "https://github.com/BishopFox/sliver"

	strings:
		$s1 = "github.com/bishopfox/sliver/client"

	condition:
		all of them and filesize < 50MB
}

rule sliver_server
{
	meta:
		description = "Bishop Fox's Sliver C2 Server"
		author = "Daniel Roberson"
		url = "https://github.com/BishopFox/sliver"

	strings:
		$s1 = "RunSliver"

	condition:
		all of them
}
