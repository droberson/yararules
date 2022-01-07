rule tar
{
	meta:
		description = "Tape archive (.tar file)"

	strings:
		$tar = "ustar"

	condition:
		$tar at 257
}
