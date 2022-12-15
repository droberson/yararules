rule go_ole : ole go
{
	meta:
		description = "Golang OLE library"
		reference = "https://github.com/go-ole/go-ole"

	strings:
		$ = "github.com/go-ole"


	condition:
		all of them
}
