rule crypto_constants_md5
{
	meta:
		author = "Daniel Roberson"
		description = "md5 crypto constants"

	strings:
		$c1 = { 01234567 }
		$c2 = { 89abcdef }
		$c3 = { fedcba98 }
		$c4 = { 76543210 }

		$r1 = { 78a46ad7 }
		$r2 = { 56b7c7e8 }
		$r3 = { db702024 }
		$r4 = { eecebdc1 }
		$r5 = { af0f7cf5 }
		$r6 = { 2ac68747 }
		$r7 = { 134630a8 }
		$r8 = { 019546fd }
		$r9 = { d8988069 }
		$r10 = { aff7448b }
		$r11 = { b15bffff }
		$r12 = { bed75c89 }
		$r13 = { 2211906b }
		$r14 = { 937198fd }
		$r15 = { 8e4379a6 }
		$r16 = { 2108b449 }
		$r17 = { 62251ef6 }
		$r18 = { 40b340c0 }
		$r19 = { 515a5e26 }
		$r20 = { aac7b6e9 }
		$r21 = { 5d102fd6 }
		$r22 = { 53144402 }
		$r23 = { 81e6a1d8 }
		$r24 = { c8fbd3e7 }
		$r25 = { e6cde121 }
		$r26 = { d60737c3 }
		$r27 = { 870dd5f4 }
		$r28 = { ed145a45 }
		$r29 = { 05e9e3a9 }
		$r30 = { f8a3effc }
		$r31 = { d9026f67 }
		$r32 = { 8a4c2a8d }
		$r33 = { 4239faff }
		$r34 = { 81f67187 }
		$r35 = { 22619d6d }
		$r36 = { 0c38e5fd }
		$r37 = { 44eabea4 }
		$r38 = { a9cfde4b }
		$r39 = { 604bbbf6 }
		$r40 = { 70bcbfbe }
		$r41 = { c67e9b28 }
		$r42 = { fa27a1ea }
		$r43 = { 8530efd4 }
		$r44 = { 051d8804 }
		$r45 = { 39d0d4d9 }
		$r46 = { e599dbe6 }
		$r47 = { f87ca21f }
		$r48 = { 6556acc4 }
		$r49 = { 442229f4 }
		$r50 = { 97ff2a43 }
		$r51 = { a72394ab }
		$r52 = { 39a093fc }
		$r53 = { c3595b65 }
		$r54 = { 92cc0c8f }
		$r55 = { 7df4efff }
		$r56 = { d15d8485 }
		$r57 = { 4f7ea86f }
		$r58 = { e0e62cfe }
		$r59 = { 144301a3 }
		/*
		ClamAV complained about having more than 64 strings...
		$r60 = { a111084e }
		$r61 = { 827e53f7 }
		$r62 = { 35f23abd }
		$r63 = { bbd2d72a }
		$r64 = { 91d386eb }
		*/

	condition:
		all of them
}
