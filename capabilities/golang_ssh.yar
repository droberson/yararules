rule golang_ssh
{
	meta:
		description = "Golang binary including ssh package"
		reference = "https://pkg.go.dev/golang.org/x/crypto/ssh"

	strings:
		$ = "golang.org/x/crypto/ssh"

	condition:
		all of them
}
