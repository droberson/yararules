rule rc4_ksa
{
 	meta:
		author = "Thomas Barabosch"
 		description = "Searches potential setup loops of RC4's KSA"
 	strings:
 		$s0 = { 3d 00 01 00 00 } // cmp eax, 256
 		$s1 = { 81 f? 00 01 00 00 } // cmp {ebx, ecx, edx}, 256
		$s2 = { 48 3d 00 01 00 00 } // cmp rax, 256
 		$s3 = { 48 81 f? 00 01 00 00 } // cmp {rbx, rcx, …}, 256
	condition:
		any of them
}

rule rc4_optimized_ksa
{
	meta:
		author = "Daniel Roberson"
		description = "Searches for potential optimized RC4 KSA implementasions"

	strings:
		//$ = { 03020100 }
		$ = { 07060504 }
		$ = { 0b0a0908 }
		$ = { 0f0e0d0c }
		$ = { 13121110 }
		$ = { 17161514 }
		$ = { 1b1a1918 }
		$ = { 1f1e1d1c }
		$ = { 23222120 }
		$ = { 27262524 }
		$ = { 2b2a2928 }
		$ = { 2f2e2d2c }
		$ = { 33323130 }
		$ = { 37363534 }
		$ = { 3b3a3938 }
		$ = { 3f3e3d3c }
		$ = { 43424140 }
		$ = { 47464544 }
		$ = { 4b4a4948 }
		$ = { 4f4e4d4c }
		$ = { 53525150 }
		$ = { 57565554 }
		$ = { 5b5a5958 }
		$ = { 5f5e5d5c }
		$ = { 63626160 }
		$ = { 67666564 }
		$ = { 6b6a6968 }
		$ = { 6f6e6d6c }
		$ = { 73727170 }
		$ = { 77767574 }
		$ = { 7b7a7978 }
		$ = { 7f7e7d7c }
		$ = { 83828180 }
		$ = { 87868584 }
		$ = { 8b8a8988 }
		$ = { 8f8e8d8c }
		$ = { 93929190 }
		$ = { 97969594 }
		$ = { 9b9a9998 }
		$ = { 9f9e9d9c }
		$ = { a3a2a1a0 }
		$ = { a7a6a5a4 }
		$ = { abaaa9a8 }
		$ = { afaeadac }
		$ = { b3b2b1b0 }
		$ = { b7b6b5b4 }
		$ = { bbbab9b8 }
		$ = { bfbebdbc }
		$ = { c3c2c1c0 }
		$ = { c7c6c5c4 }
		$ = { cbcac9c8 }
		$ = { cfcecdcc }
		$ = { d3d2d1d0 }
		$ = { d7d6d5d4 }
		$ = { dbdad9d8 }
		$ = { dfdedddc }
		$ = { e3e2e1e0 }
		$ = { e7e6e5e4 }
		$ = { ebeae9e8 }
		$ = { efeeedec }
		$ = { f3f2f1f0 }
		$ = { f7f6f5f4 }
		$ = { fbfaf9f8 }
		$ = { fffefdfc }

	condition:
		all of them
}

