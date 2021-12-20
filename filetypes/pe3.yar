rule pe_file_method1
{
	meta:
		description = "PE file 'MZ' header as string"
		author = "Daniel Roberson"

	strings:
		$pe = "MZ"

	condition:
		$pe at 0
}
/*
for i in $(seq 10); do (time yara -r /home/daniel/code/yararules/pe3.yar /home/daniel/Downloads/malware_data_science 2>&1 >/dev/null) 2>&1 |awk {'print $7'}; done
7.27s
6.69s
6.56s
6.44s
6.52s
6.81s
6.48s
6.56s
6.42s
6.36s

*/
