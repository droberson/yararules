rule ar_file
{
	meta:
		description = "Unix 'ar' archive file"
		reference = "https://handwiki.org/wiki/Software:Ar_(Unix)#File_signature"

	strings:
		$header = { 21 3c 61 72 63 68 3e 0a } /* "!<arch>\n" */

	condition:
		$header at 0
}
