rule shell_script_linguist
{
	meta:
		description = "Match *nix shell scripts"

	strings:
		$s1 = "echo" fullword
		$s2 = "read" fullword
		$s3 = "set" fullword
		$s4 = "unset" fullword
		$s5 = "shift" fullword
		$s6 = "export" fullword
		$if1 = "if" fullword
		$if2 = "fi" fullword
		$if3 = "then" fullword
		$if4 = "else" fullword
		$loop1 = "while" fullword
		$loop2 = "do" fullword
		$loop3 = "done" fullword
		$loop4 = "for" fullword
		$case1 = "case" fullword
		$case2 = "esac" fullword
		$case3 = "in" fullword
		$s7 = "ulimit" fullword
		$s8 = "umask" fullword
		$s9 = "eval" fullword
		$s10 = "exec" fullword
		$elf = "\x7fELF"
		$pe = "MZ"

	condition:
		3 of ($s*) and (3 of ($if*) or 3 of ($case*) or 3 of ($loop*)) and (not $elf at 0 and not $pe at 0)
}
