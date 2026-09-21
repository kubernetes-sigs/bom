---
title: "bom"
linkTitle: "bom"
tags: ["reference"]
date: 2026-09-21
description: A tool for working with SPDX manifests

---

## bom

A tool for working with SPDX manifests

### Synopsis

bom (Bill of Materials)

bom is a little utility that lets software authors generate
SPDX manifests to describe the contents of a release. The
SPDX manifests provide a way to list and verify all items
contained in packages, images, and individual files while
packing the data along with licensing information.

bom is still in its early stages and it is an effort to open
the libraries developed for the Kubernetes SBOM for other
projects to use.



### Options

```
  -h, --help               help for bom
      --log-level string   the logging verbosity, either 'panic', 'fatal', 'error', 'warning', 'info', 'debug', 'trace' (default "info")
```

### SEE ALSO

* [bom document](bom_document.md)	 - bom document → Work with SPDX documents
* [bom generate](bom_generate.md)	 - bom generate → Create SPDX SBOMs
* [bom validate](bom_validate.md)	 - bom validate → Check artifacts against an sbom
* [bom version](bom_version.md)	 - Prints the version

