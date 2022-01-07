rule ole_file
{
	meta:
		description = "OLE file"

	condition:
		uint32(4) == 0xe11ab1a1 and uint32(0) == 0xe011cfd0
}

rule msi_file
{
	meta:
		description = "MSI file"

	strings:
		$msi_clsid = { 84 10 0c 00 00 00 00 00 c0 00 00 00 00 00 00 46 }

	condition:
		uint32(4) == 0xe11ab1a1 and uint32(0) == 0xe011cfd0 and
		$msi_clsid at (512 * (1 + uint32(48)) + 80)
}

rule word_file
{
	meta:
		description = "Microsoft Office Word file"

	strings:
		$doc_clsid1 = { 06 09 02 00 00 00 00 00 c0 00 00 00 00 00 00 46 }

	condition:
		uint32(4) == 0xe11ab1a1 and uint32(0) == 0xe011cfd0 and
		$doc_clsid1 at (512 * (1 + uint32(48)) + 80)
}

rule powerpoint_file
{
	meta:
		description = "Microsoft Office PowerPoint file"

	strings:
		$ppt_clsid1 = { 10 8d 81 64 9b 4f cf 11 86 ea 00 aa 00 b9 29 e8 }

	condition:
		uint32(4) == 0xe11ab1a1 and uint32(0) == 0xe011cfd0 and
		$ppt_clsid1 at (512 * (1 + uint32(48)) + 80)
}

rule excel_file
{
	meta:
		description = "Microsoft Office Excel file"

	strings:
		$xls_clsid1 = { 20 08 02 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
		$xls_clsid2 = { 10 08 02 00 00 00 00 00 c0 00 00 00 00 00 00 46 }

	condition:
		uint32(4) == 0xe11ab1a1 and uint32(0) == 0xe011cfd0 and
		($xls_clsid1 at (512 * (1 + uint32(48)) + 80) or
		 $xls_clsid2 at (512 * (1 + uint32(48)) + 80)
		)
}

rule outlook_message_file
{
	meta:
		description = "Microsoft Outlook MSG file"

	strings:
		$outlook_clsid1 = { 0b 0d 02 00 00 00 00 00 c0 00 00 00 00 00 00 46 }

	condition:
		uint32(4) == 0xe11ab1a1 and uint32(0) == 0xe011cfd0 and
		$outlook_clsid1 at (512 * (1 + uint32(48)) + 80)
}

rule ole_unspecified_file
{
	meta:
		description = "OLE file, unspecified (SUO, Thumbsdb, ...)"

	strings:
		$unk_clsid1 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		uint32(4) == 0xe11ab1a1 and uint32(0) == 0xe011cfd0 and
		$unk_clsid1 at (512 * (1 + uint32(48)) + 80)
}
