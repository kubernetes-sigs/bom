---
title: "bom validate"
linkTitle: "bom validate"
tags: ["reference"]
date: 2022-06-27
description: bom validate → Check artifacts against SPDX manifests

---

## bom validate

### Synopsis

bom validate → Check artifacts against an sbom

validate is the bom subcommand to check artifacts against SPDX
manifests.

This is an experimental command. The first iteration has support
for checking files.



```
bom validate [flags]
```

### Options

```
  -e, --exit-code       when true, bom will exit with exit code 1 if invalid artifacts are found
  -f, --files strings   list of files to verify
  -h, --help            help for validate
```

### Options inherited from parent commands

```
      --log-level string   the logging verbosity, either 'panic', 'fatal', 'error', 'warning', 'info', 'debug', 'trace' (default "info")
```

### SEE ALSO

* [bom](bom.md)	 - A tool for working with SPDX manifests

###### Auto generated by spf13/cobra on 27-Jun-2022
