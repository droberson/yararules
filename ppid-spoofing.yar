rule ppid_spoofing
{
	meta:
		author = "Daniel Roberson"
		description = "Detect Windows binaries and scripts which may have implemented Parent Process ID (PPID) spoofing."
		hash = "34f5ae67f3cfb6e0a64f2680ea59210fe17055c9360af57cc820d61f576e42c5"
		url = "https://github.com/py7hagoras/GetSystem"

	strings:
		$s1 = "InitializeProcThreadAttributeList"
		$s2 = "OpenProcess"
		$s3 = "DuplicateHandle"
		$s4 = "UpdateProcThreadAttribute"
		$s5 = "CreateProcess"

		/*$x1 = "InitializeProcThreadAttributeList" xor
		$x2 = "OpenProcess" xor
		$x3 = "DuplicateHandle" xor
		$x4 = "UpdateProcThreadAttribute" xor
		$x5 = "CreateProcess" xor*/

	condition:
		all of ($s*) //or all of ($x*)
}
