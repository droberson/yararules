rule cephi_infected
{
	meta:
		description = "Detect files impacted by Cephi file infector"
		reference = "https://github.com/guitmz/nim-cephei"
		hash = "35308b8b770d2d4f78299262f595a0769e55152cb432d0efc42292db01609a18"

	strings:
		$ = "infect_"
		$ = "xorEncDec_"
		$ = "isInfected_"

	condition:
		uint32(0) == 0x464c457f and all of them
}
