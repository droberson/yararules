rule discord_cdn
{
	meta:
		description = "Contains 'cdn.discordapp.com' string"

	strings:
		$ = "cdn.discordapp.com" ascii wide nocase

	condition:
		all of them
}
