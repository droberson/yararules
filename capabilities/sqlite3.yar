rule go_sqlite3
{
	strings:
		$ = "github.com/mattn/go-sqlite3"
	condition:
		all of them
}

rule sqlite3_extension
{
	strings:
		$ = "sqlite3_extension_init" fullword
	condition:
		all of them

}
