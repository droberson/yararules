import "pe"

rule contains_pdb_path
{
	meta:
		description = "PE file containing PDB path"
		prereq = "Requires yara v4.0.0+"

	condition:
		pe.pdb_path
}
