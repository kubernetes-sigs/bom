---
title: "bom document outline"
linkTitle: "bom document outline"
tags: ["reference"]
date: 2022-06-27
description: bom document query → Draw structure of a SPDX document

---

## bom document outline

bom document outline → Draw structure of a SPDX document

### Synopsis

bom document outline → Draw structure of a SPDX document",

This subcommand draws a tree-like outline to help the user visualize
the structure of the bom. Even when an SBOM represents a graph structure,
drawing a tree helps a lot to understand what is contained in the document.

You can define a level of depth to limit the expansion of the entities.
For example set --depth=1 to only visualize only the files and packages
attached directly to the root of the document.

bom will try to add useful information to the oultine but, if needed, you can
set the --spdx-ids to only output the IDs of the entities.



```
bom document outline SPDX_FILE [flags]
```

### Options

```
  -d, --depth int   recursion level (default -1)
  -h, --help        help for outline
      --spdx-ids    use SPDX identifiers in tree nodes instead of names
```

### Options inherited from parent commands

```
      --log-level string   the logging verbosity, either 'panic', 'fatal', 'error', 'warning', 'info', 'debug', 'trace' (default "info")
```

### SEE ALSO

* [bom document](bom_document.md)	 - bom document → Work with SPDX documents

###### Auto generated by spf13/cobra on 27-Jun-2022
