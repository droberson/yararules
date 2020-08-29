rule Ox333shadow
{
	meta:
		author = "Daniel Roberson"
		description = "https://packetstormsecurity.com/files/31345/0x333shadow.tar.gz.html"

	strings:
		$s1 = "[WARNING]: syslogd not killed!"
		$s2 = "[*] snoopy not detected."
		$s3 = "i believe you have to be root, for run me. open your mind!"
		$s4 = "[*] founded %s"
		$s5 = "getpidsysanotherway"

	condition:
		uint32(0) == 0x464c457f
		and any of them
}

