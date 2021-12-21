rule golang
{
	meta:
		description = "Golang binary"

	strings:
		$s1 = "Go build"
		$s2 = "go.build"
		$go = "/go-"

	condition:
		any of ($s*) or #go > 10
}
