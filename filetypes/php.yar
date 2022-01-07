rule php
{
	meta:
		description = "PHP file"

	strings:
		$php = "<?php" ascii wide nocase

	condition:
		$php at 0
}
