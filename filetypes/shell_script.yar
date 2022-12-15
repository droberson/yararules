rule shell_script
{
	meta:
		description = "Shell scripts"

	strings:
		$s1 = "#!/bin/sh"
		$s2 = "#!/bin/bash"
		$s3 = "#!/bin/zsh"
		$s4 = "#!/bin/csh"
		$s5 = "#!/bin/tcsh"
		$s6 = "#! /bin/sh"

	condition:
		$s1 at 0 or
		$s2 at 0 or
		$s3 at 0 or
		$s4 at 0 or
		$s5 at 0 or
		$s6 at 0
}
