rule efspotato
{
	meta:
		author = "Daniel Roberson"
		description = "EfsPotato privilege escalation exploit"
		reference = "https://github.com/zcgonvh/EfsPotato"
		hash = "53872999793974075bab4f59cd41c493cf7475851193c4bac1b9287336529d57"

	strings:
		$efspotato = "EfsPotato"

	condition:
		uint16(0) == 0x5a4d and $efspotato
}
