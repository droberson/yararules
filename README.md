# yara rules
Here are some yara rules. Use at your own risk.


## Yara CLI
```
yara /path/to/rule.yar -r /path/to/scan/
```

## ClamAV
```
clamscan --allmatch --infected -r -d /path/to/rules/ /path/scan/
```
