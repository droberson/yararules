rule hive_ransomware_string_obfuscation
{
	meta:
		description = "Hive Ransomware obfuscated strings"

	strings:
		$obfuscated1 = /[a-zA-Z0-9]{8}\.[a-zA-Z0-9_]{8}\.String\.func/
		$obfuscated2 = /[a-zA-Z0-9]{8}\.\(\*[a-zA-Z0-9]{8}\)\.[a-zA-Z0-9]{10}/

	condition:
		#obfuscated1 > 10 or #obfuscated2 > 10
}
