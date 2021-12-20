rule macho
{
	meta:
		description = "Mach-O binaries"

	condition:
		uint32(0) == 0xfeedface or /* 32 bit */
		uint32(0) == 0xcefaedfe or /* NXSwapInt(MH_MAGIC */
		uint32(0) == 0xfeedfacf or /* 64 bit */
		uint32(0) == 0xcffaedfe or /* NXSwapInt(MH_MAGIC_64) */
		uint32(0) == 0xcafebabe or /* FAT, Java */
		uint32(0) == 0xbebafeca or /* NXSwapInt(FAT_MAGIC) */
		uint32(0) == 0xcafebabf or /* FAT 64 bit */
		uint32(0) == 0xbfbafeca    /* NXSwapLong(FAT_MAGIC_64) */
}
