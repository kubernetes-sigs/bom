---
title: "bom validate"
linkTitle: "bom validate"
tags: ["reference"]
date: 2026-09-21
description: bom validate → Check artifacts against an sbom

---

## bom validate

bom validate → Check artifacts against an sbom

### Synopsis

bom validate → Check artifacts against an sbom

validate is the bom subcommand to check artifacts against SPDX
manifests: the checksums of each file are compared to those the
SBOM records for it.

The first argument is the SBOM, any further ones files to check.
With --dir, every file in a directory is checked against the files
of the package describing it, as bom generate --dirs records them:

  bom validate sbom.spdx.json --dir .

This is an experimental command. The first iteration has support
for checking files.



```
bom validate SBOM_FILE [FILE...] [flags]
```

### Options

```
  -d, --dir string      a whole directory to verify
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

