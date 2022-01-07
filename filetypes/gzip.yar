rule gzip_file
{
	meta:
		description = "gzipped file"

	strings:
		$gzip = { 1f 8b 08 }

	condition:
		$gzip at 0
}
