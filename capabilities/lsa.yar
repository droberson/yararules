rule lsa_registry_strings
{
	meta:
		description = "Contains Windows LSA registry strings"
		reference = "https://pentestlab.blog/2019/10/21/persistence-security-support-provider/"

	strings:
		$ = "SYSTEM\\CurrentControlSet\\Control\\LSA" ascii wide nocase

	condition:
		any of them
}
