rule crypto_constants_crc32
{
	meta:
		author = "Daniel Roberson"
		description = "crc32 constants"

	strings:
		$r4 = { 96300777 }
		$r5 = { 2c610eee }
		$r6 = { ba510999 }
		$r7 = { 19c46d07 }
		$r8 = { 8ff46a70 }
/*$r9 = { 35a563e9 }
$r10 = { a395649e }
$r11 = { 3288db0e }
$r12 = { a4b8dc79 }
$r13 = { 1ee9d5e0 }
$r14 = { 88d9d297 }
$r15 = { 2b4cb609 }
$r16 = { bd7cb17e }
$r17 = { 072db8e7 }
$r18 = { 911dbf90 }
$r19 = { 6410b71d }
$r20 = { f220b06a }
$r21 = { 4871b9f3 }
$r22 = { de41be84 }
$r23 = { 7dd4da1a }
$r24 = { ebe4dd6d }
$r25 = { 51b5d4f4 }
$r26 = { c785d383 }
$r27 = { 56986c13 }
*/
	condition:
		all of them
}
