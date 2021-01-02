# yara rules
Here are some yara rules.

The Makefile in this directory will bundle all of these up into a tarball
for make more easy.

```
make
```

## using with clamav
```
clamscan --allmatch --infected -r -d /path/to/directory/of/yara/rules /path/to/directory/to/scan
```

