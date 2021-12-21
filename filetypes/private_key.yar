rule private_key
{
	meta:
		description = "Private key"

	strings:
		$ = "BEGIN PRIVATE KEY" ascii wide

	condition:
		all of them
}

rule private_rsa_key
{
	meta:
		description = "RSA private key"

	strings:
		$ = "BEGIN RSA PRIVATE KEY" ascii wide

	condition:
		all of them
}
