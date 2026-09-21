---
title: "bom generate"
linkTitle: "bom generate"
tags: ["reference"]
date: 2026-09-21
description: bom generate → Create SPDX SBOMs

---

## bom generate

bom generate → Create SPDX SBOMs

### Synopsis

bom generate → Create SPDX SBOMs

generate is the bom subcommand to generate SPDX manifests.

Currently supports creating SBOM from files, images, and docker
archives (images in tarballs). It supports pulling images from
remote registries for analysis.

bom can take a deeper look into images using a growing number
of analyzers designed to add more sense to common base images.

Go binaries found in images and in files passed with --file are
listed with the Go modules they were built from, as recorded in
their embedded build information.

The SBOM data can also be exported to an in-toto provenance
attestation. The output will produce a provenance statement listing all
the SPDX data as in-toto subjects, but otherwise ready to be
completed by a later stage in your CI/CD pipeline. See the
--provenance flag for more details.



```
bom generate [flags]
```

### Options

```
      --archive strings               list of archives to add as packages (supports tar, tar.gz)
  -c, --config string                 path to yaml SBOM configuration file
  -d, --dirs strings                  list of directories to include in the manifest as packages
  -f, --file strings                  list of files to include
      --format string                 format of the document (supports json, tag-value) (default "json")
  -h, --help                          help for generate
      --ignore strings                list of gitignore-style patterns to ignore when scanning directories
  -i, --image strings                 list of images
      --image-archive strings         list of docker archive tarballs to include in the manifest
      --license-list-version string   version of the SPDX license list to record in the document (default "v3.28.0")
      --name string                   name for the document, in contrast to URLs, intended for humans
  -n, --namespace string              an URI that serves as namespace for the SPDX doc
      --no-gitignore                  don't use exclusions from .gitignore files
      --no-transient                  don't resolve dependencies beyond those a codebase requires in its go.mod
      --offline                       don't reach the network: dependency data is read from local files only
  -o, --output string                 path to the file where the document will be written (defaults to STDOUT)
      --provenance string             path to export the SBOM as an in-toto provenance statement
```

### Options inherited from parent commands

```
      --log-level string   the logging verbosity, either 'panic', 'fatal', 'error', 'warning', 'info', 'debug', 'trace' (default "info")
```

### SEE ALSO

* [bom](bom.md)	 - A tool for working with SPDX manifests

