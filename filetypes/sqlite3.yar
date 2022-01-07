rule sqlite3
{
	meta:
		description = "SQLite3 database"

	strings:
		$sqlite3 = "SQLite format 3"

	condition:
		$sqlite3 at 0
}
