---
title: "bom document query"
linkTitle: "bom document query"
tags: ["reference"]
date: 2026-09-21
description: bom document query → Search for information in an SBOM

---

## bom document query

bom document query → Search for information in an SBOM

### Synopsis

bom document query → Search for information in an SBOM

The query subcommand creates a way to extract information
from an SBOM. It exposes a simple search language to filter
elements in the sbom that match a certain criteria.

The query interface allows the number of filters to grow
over time. The following filters are available:

  depth:N       The depth filter will match elements
                reachable at N levels from the document root.
                For example, to find all elements, one level
                deep from the SBOM top level:

                bom document query sbom.spdx.json "depth:1"


  name:pattern  Matches all elements in the document that
                match the regex <pattern> in their name. For example,
                to find all packages with 'lib' and a 'c' in their name:

                bom document query sbom.spdx.json 'name:lib.*c'

  purl:pattern  Matches all elements in the document that match
                fragments of a purl. Components left out or set to *
                match anything, and a * in the namespace matches one or
                more of its segments. For example, to get all container
                images listed in an SBOM you can issue a query like this:

                bom document query sbom.spdx.json 'purl:pkg:oci/*'

                or to get all Go modules hosted on GitHub:

                bom document query sbom.spdx.json 'purl:pkg:golang/github.com/*'

The name and purl filters stop at the first element that matches on
each branch of the document, so elements below a match are not searched.

You can query files piped on STDIN by specifying the path as a dash (-) or
omitting it completely. These are equivalent:

    cat sbom.spdx.json | bom document query - 'name:log4j'
    cat sbom.spdx.json | bom document query 'name:log4j'

Example:

  # Match all second level elements with log4j in their name:
  bom document query sbom.spdx.json "depth:2 name:log4j"



```
bom document query sbom.spdx.json "query expression"  [flags]
```

### Options

```
      --fields strings   fields to include in output, separated by commas: name,version,license,supplier,originator,url, (default [name])
      --format string    format of output, one of: text, csv or json (default "text")
  -h, --help             help for query
      --purl             output package urls instead of name@version
```

### Options inherited from parent commands

```
      --log-level string   the logging verbosity, either 'panic', 'fatal', 'error', 'warning', 'info', 'debug', 'trace' (default "info")
```

### SEE ALSO

* [bom document](bom_document.md)	 - bom document → Work with SPDX documents

