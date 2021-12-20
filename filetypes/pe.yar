import "pe"

rule pe_file_method3
{
	meta:
		description = "PE File 'MZ' header"
		author = "Daniel Roberson"

	condition:
		pe.is_pe
}
/* yara -r /home/daniel/code/yararules/pe.yar   35.41s user 2.72s system 697% cpu 5.462 total
for i in $(seq 10); do (time yara -r /home/daniel/code/yararules/pe.yar /home/daniel/Downloads/malware_data_science 2>&1 >/dev/null) 2>&1 |awk {'print $7'}; done
36.51s
37.07s
37.48s
38.06s
38.60s
38.95s
39.17s
39.16s
39.64s
39.47s

*/
