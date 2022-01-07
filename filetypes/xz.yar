rule xz
{
	meta:
		description = "xz file"

	strings:
		$xz = { fd 37 7a 58 5a }

	condition:
		$xz at 0
}
