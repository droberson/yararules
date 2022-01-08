import "pe"

rule pe_overlay
{
	meta:
		description = "PE file containing an overlay"

	condition:
		pe.overlay.size > 0
}

import "math"

rule pe_overlay_high_entropy
{
	meta:
		description = "PE files with a high entropy overlay"

	condition:
		math.entropy(pe.overlay.offset, filesize) > 6.5
}

rule pe_overlay_large
{
	meta:
		description = "PE file with large overlay"

	condition:
		pe.overlay.size > pe.size_of_code
}
