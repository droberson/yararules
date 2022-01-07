rule xml
{
	meta:
		description = "XML file"

	strings:
		$xml = "<?xml" ascii wide nocase

	condition:
		$xml at 0
}
