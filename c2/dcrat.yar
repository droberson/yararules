import "dotnet"

rule DCRat
{
	meta:
		author = "Daniel Roberson"
		reference = "https://github.com/qwqdanchun/DcRat"
		description = "Detect DcRat"
		hash = "c73b1ffa39c5843b2ed951ac48350d1deb33db4057341f1dab1ee64ea1a62248"

	condition:
		dotnet.assembly.name == "DcRat"
}
