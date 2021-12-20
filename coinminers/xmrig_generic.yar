rule xmrig_generic
{
	meta:
		author = "Daniel Roberson"
		description = "https://github.com/xmrig/xmrig*"

	strings:
		$s1 = "https://xmrig.com"

	condition:
		(uint32(0) == 0x464c457f or uint16(0) == 0x5a4d or uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca)
		and all of them
}

