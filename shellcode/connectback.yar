rule connectback
{
  meta:
		author = "Daniel Roberson"
		description = "ConnectBack shellcode used in Gitlab intrusions"
		hash = "cd54a34dbd7d345a7fd7fd8744feb5c956825317e9225edb002c3258683947f1"

	strings:
		$elf = { 7f 45 4c 46 }
		$s = { 48 31 FF 6A 09 58 99 B6 10 48 89 D6 4D 31 C9 6A 22 41 5A B2 07 0F 05 48 85 C0 78 51 6A 0A 41 59 50 6A 29 58 99 6A 02 5F 6A 01 5E 0F 05 48 85 C0 78 3B 48 97 48 B9 02 00 ?? ?? ?? ?? ?? ?? 51 48 89 E6 6A 10 5A 6A 2A 58 0F 05 59 48 85 C0 79 25 49 FF C9 74 18 57 6A 23 58 6A 00 6A 05 48 89 E7 48 31 F6 0F 05 59 59 5F 48 85 C0 79 C7 6A 3C 58 6A 01 5F 0F 05 5E 6A 7E 5A 0F 05 48 85 C0 78 ED FF E6 }

	condition:
		$elf at 0 and all of them
}
