# yara rules
Here are some yara rules. Use at your own risk.

The Makefile in this directory will bundle all of these up into a tarball.
```
make
```

## Yara CLI
```
yara /path/to/rule.yar -r /path/to/scan/
```

## ClamAV
```
clamscan --allmatch --infected -r -d /path/to/rules/ /path/scan/
```
