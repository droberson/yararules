rule libprocesshider
{
	meta:
		description = "libprocesshider userland rootkit"

	strings:
		$ = "%d (%[^)]s"
		$ = "/proc/self/fd/%d"
		$ = "/proc/%s/stat"
		$ = "dlsym"

	condition:
		all of them
}
