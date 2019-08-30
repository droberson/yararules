all:
	rm -f yara.tar.gz
	tar -cf yara.tar *
	gzip -9 yara.tar

