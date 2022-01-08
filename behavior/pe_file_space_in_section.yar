import "pe"

rule pe_file_space_in_section
{
	meta:
		description = "PE file containing a section with a space in it's name"
		reference = "https://twitter.com/greglesnewich/status/1479430616999419904"

	condition:
		for any s in pe.sections: (s.name contains " ")
}
