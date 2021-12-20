rule pe_file_method2
{
	meta:
		description = "PE file 'MZ' header as uint16"
		author = "Daniel Roberson"

	condition:
		uint16(0) == 0x5a4d
}
/*
for i in $(seq 10); do (time yara -r /home/daniel/code/yararules/pe2.yar /home/daniel/Downloads/malware_data_science 2>&1 >/dev/null) 2>&1 |awk {'print $7'}; done
6.57s
6.33s
6.15s
6.30s
6.47s
6.45s
6.28s
6.17s
6.28s
6.31s
*/
