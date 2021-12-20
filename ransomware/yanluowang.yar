rule yanluowang_pdb
{
	meta:
		description = "PDB path found in Yanluowang ransomware samples"

	strings:
		$ = "C:\Users\111\Desktop\wifi\project\ConsoleApplication2\Release\ConsoleApplication2.pdb"

	condition:
		all of them
}
