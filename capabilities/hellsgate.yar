rule hellsgate
{
	meta:
		description = "modified djb2 hash used in Hell's Gate samples"
		reference = "https://github.com/vxunderground/VXUG-Papers/blob/main/Hells%20Gate/C%20Implementation/HellsGate/main.c"

	strings:
		$hellsgate = { 34 77 34 77 [2-60] c1 ?? 05 }

	condition:
		all of them
}

