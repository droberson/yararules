rule djb2
{
	meta:
		description = "djb2 hash. used by malware for API and string hashing"

	strings:
		$dbj2_1 = { 05 15 00 00 [1-30] c1 ?? 05 } // 5381 .. shl ??¸ 5

	condition:
		all of them
}

