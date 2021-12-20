rule sha256_constants
{
	meta:
		description = "SHA256 constants"

	strings:
		$ = { 852c7292 }
		$ = { a1e8bfa2 }
		$ = { 4b661aa8 }
		$ = { 708b4bc2 }
		$ = { a3516cc7 }
		$ = { 19e892d1 }
		$ = { 240699d6 }
		$ = { 85350ef4 }
		$ = { 70a06a10 }
		$ = { 16c1a419 }
		$ = { 086c371e }
		$ = { 4c774827 }
		$ = { b5bcb034 }
		$ = { b30c1c39 }
		$ = { 4aaad84e }
		$ = { 4fca9c5b }
		$ = { f36f2e68 }
		$ = { ee828f74 }

		$ = { 6f63a578 }
		$ = { 1478c884 }
		$ = { 0802c78c }
		$ = { faffbe90 }
		$ = { eb6c50a4 }
		$ = { f7a3f9be }
		$ = { f27871c6 }

	condition:
		all of them
}
