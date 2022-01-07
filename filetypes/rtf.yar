rule rtf
{
	meta:
		description = "RTF file"

	strings:
		$rtf = "{\\rtf"

	condition:
		$rtf at 0
}
