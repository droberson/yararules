rule murmurhash_constants
{
	meta:
		author = "Daniel Roberson"
		description = "mmh3 constants"

	strings:
		$c1 = { 512d9ecc }
		$c2 = { 9335871b }
		$c3 = { 646b54e6 }
		$c4 = { 35aeb2c2 }

	condition:
		all of them
}
