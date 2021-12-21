rule openssh_private_key
{
	meta:
		description = "OpenSSH private key"

	strings:
		$ = "-----BEGIN OPENSSH PRIVATE KEY-----"

	condition:
		all of them
}
