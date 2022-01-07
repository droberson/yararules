rule iso9660
{
	meta:
		description = "ISO 9660 (.iso file)"

	strings:
		$iso9660 = { 01 43 44 30 30 31 } // .CD001

	condition:
		$iso9660 at 32768
}
