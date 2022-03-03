rule hellsgate
{
	meta:
		description = "Modified djb2 hash used in Hell's Gate samples"
		reference = "https://github.com/vxunderground/VXUG-Papers/blob/main/Hells%20Gate/C%20Implementation/HellsGate/main.c"
		hash = "a5acaaf2b7bb02a18b33ac2428863811be8ddfa587e6e4b0d6b0ae563df2377c"
	strings:
		$hellsgate = { 34 77 34 77 [2-60] c1 ?? 05 } // 3477 ... shl ??, 5

	condition:
		all of them
}

