rule linux_capability_file_download
{
	meta:
		author = "Daniel Roberson"
		description = "Potential capability: file download"

	strings:
		$s1 = "socket"
		$s2 = "accept"

	condition:
		all of them
}
