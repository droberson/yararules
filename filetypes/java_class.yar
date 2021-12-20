// TODO false positives w/ mach-o
// TODO does this matter on big endian systems?

rule java_class_compiled
{
	meta:
		description = "Java Class"

	condition:
		uint32(0) == 0xbebafeca
}
