---
title: "bom document dot"
linkTitle: "bom document dot"
tags: ["reference"]
date: 2026-09-21
description: bom document dot → Export the SBOM graph in Graphviz DOT format

---

## bom document dot

bom document dot → Export the SBOM graph in Graphviz DOT format

### Synopsis

bom document dot → Export the SBOM graph in Graphviz DOT format

This subcommand writes the relationship graph of an SBOM in the DOT
language (https://graphviz.org/doc/info/lang.html) to STDOUT, ready to
be rendered with Graphviz or any other tool that reads DOT:

  bom document dot sbom.spdx.json | dot -Tsvg > sbom.svg

Unlike the tree drawn by 'bom document outline', every element appears
once: an element related to several others is a single node with an
edge from each of them, and each edge is labelled with its SPDX
relationship types.

Use --root to render only the part of the graph reachable from one
element, and --depth to limit how many relationship steps are followed.
For example, --depth=1 renders only the elements at the top level of
the document, or with --root, the root element and the elements it
relates to directly. Large SBOMs are easier to read with --no-files,
which leaves file elements out.

SPDX documents in JSON or tag-value and CycloneDX documents are
supported. The document can also be read from a URL or piped on STDIN
by specifying the path as a dash (-) or omitting it.

```
bom document dot SBOM_FILE|URL [flags]
```

### Options

```
  -d, --depth int     number of relationship steps to follow, zero or negative for all (default -1)
  -h, --help          help for dot
      --no-files      leave file elements out of the graph
      --purl          label packages with their package URL instead of name@version
  -r, --root string   ID of the element to render the graph from, instead of the document
```

### Options inherited from parent commands

```
      --log-level string   the logging verbosity, either 'panic', 'fatal', 'error', 'warning', 'info', 'debug', 'trace' (default "info")
```

### SEE ALSO

* [bom document](bom_document.md)	 - bom document → Work with SPDX documents
