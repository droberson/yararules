rule linux_capability_file_upload
{
	meta:
		author = "Daniel Roberson"
		description = "Potential capability: file upload"

	strings:
		$s1 = "socket"
		$s2 = "connect"

	condition:
		all of them
}
