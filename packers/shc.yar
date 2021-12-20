rule shc
{
	meta:
		description = "Compiled with generic shell script compiler (shc)"
		reference = "https://github.com/neurobin/shc"
		decompiler = "https://github.com/yanncam/UnSHc"

	strings:
		$ = "=%lu %d"
		$ = "%lu %d%c"
		$ = "%s%s%s: %s"

	condition:
		uint32(0) == 0x464c457f and all of them
}
