rule golang
{
	meta:
		description = "Golang binary"

	strings:
		$go = "/go-"

	condition:
		#go > 10
}
