rule golang_protobuf
{
	meta:
		description = "Golang binary with Google protobuf package"

	strings:
		$ = "google.golang.org/protobuf"

	condition:
		all of them
}
