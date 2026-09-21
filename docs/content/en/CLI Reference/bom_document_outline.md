---
title: "bom document outline"
linkTitle: "bom document outline"
tags: ["reference"]
date: 2026-09-21
description: bom document outline → Draw structure of a SPDX document

---

## bom document outline

bom document outline → Draw structure of a SPDX document

### Synopsis

bom document outline → Draw structure of a SPDX document

This subcommand draws a tree-like outline to help the user visualize
the structure of the bom. Even when an SBOM represents a graph structure,
drawing a tree helps a lot to understand what is contained in the document.
To see each element only once, with all the relationships leading to it,
export the graph with 'bom document dot' instead.

You can define a level of depth to limit the expansion of the entities.
For example set --depth=1 to only visualize the files and packages
attached directly to the root of the document.

Packages are labelled with their name and version, or with their package
URL when --purl is set; --version=false drops the versions and
--spdx-ids replaces the labels with the SPDX identifiers of the entities.

To see where a package comes from, --find NAME draws only the branches of
the tree that lead to elements named NAME.

SPDX documents in JSON or tag-value and CycloneDX documents are
supported. The document can also be read from a URL or piped on STDIN
by specifying the path as a dash (-) or omitting it.



```
bom document outline SPDX_FILE|URL [flags]
```

### Options

```
  -d, --depth int     recursion level (default -1)
  -f, --find string   only draw the branches leading to elements with this name
  -h, --help          help for outline
      --purl          show package urls instead of name@version
      --spdx-ids      use SPDX identifiers in tree nodes instead of names
      --version       show versions along with package names (default true)
```

### Options inherited from parent commands

```
      --log-level string   the logging verbosity, either 'panic', 'fatal', 'error', 'warning', 'info', 'debug', 'trace' (default "info")
```

### SEE ALSO

* [bom document](bom_document.md)	 - bom document → Work with SPDX documents

