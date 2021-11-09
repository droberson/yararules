rule atypical_dos_stub
{
	meta:
		description = "Find PE files with atypical DOS stubs."
		author      = "Daniel Roberson"

	strings:
		// This program cannot be run in DOS mode.
		$s1 = { ?? 1f ba 0e 00 b4 09 cd ?? b8 01 4c cd ?? 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 ?? 6f 64 65 2e 0d (0d | 0a) (0a | 24) (24 | 00) 00 00 00 00 00 00 00 }

		// This program must be run under Win32
		$s2 = { (ba | bb) (10 | 11) (00 | 01) (0e | 0f) (1f | 1e) (b4 | b5) (09 | 0a) cd 21 b8 01 4c cd 21 90 90 54 68 69 73 20 70 72 6f 67 72 61 6d 20 6d 75 73 74 20 62 65 20 72 75 6e 20 75 6e 64 65 72 20 57 69 6e 33 32 (0d | 0a) (0a | 0d) 24 37 00 00 00 00 (00 | 50) (00 | 45) 00 00 }

		// This program requires Microsoft Windows
		$s3 = { 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 72 65 71 75 69 72 65 73 20 4d 69 63 72 6f 73 6f 66 74 20 57 69 6e 64 6f 77 73 2e 0d 0a 24 00 00 00 00 00 00 00 }
		
		// NULLs
		$s4 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		uint16(0) == 0x5A4D and  /* MZ header */
		uint16(64) != 0x4550 and /* PE header at 64 suggests no DOS stub */
		not ($s1 at 64 or
		     $s2 at 64 or
		     $s3 at 64 or
		     $s4 at 64)
}
