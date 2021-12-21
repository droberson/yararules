rule base64_alphabet
{
	meta:
		description = "Base64 alphabet"

	strings:
		$ = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ascii wide

	condition:
		all of them
}
