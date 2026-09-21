# `bom`: The SBOM Multitool

[![PkgGoDev](https://pkg.go.dev/badge/sigs.k8s.io/bom)](https://pkg.go.dev/sigs.k8s.io/bom)
[![Go Report Card](https://goreportcard.com/badge/sigs.k8s.io/bom)](https://goreportcard.com/report/sigs.k8s.io/bom)
[![Slack](https://img.shields.io/badge/Slack-%23release--management-blueviolet)](https://kubernetes.slack.com/archives/C2C40FMNF)

 ![bom The SBOM Multitool](logo/logo.png)



## What is `bom`?

`bom` is a utility that lets you create, view and transform Software Bills of
Materials (SBOMs). `bom` was created as part of the project to create an SBOM
for the Kubernetes project. It enables software authors to generate an
SBOM for their projects in a simple, yet powerful way.

bom is a project incubating in the Linux Foundation's
[Automating Compliance Toling TAC](https://github.com/act-project/TAC)

`bom` is a general-purpose tool that can generate SPDX packages from
directories, container images, single files, and other sources. The utility
has a built-in license classifier that recognizes the 400+ licenses in
the SPDX catalog.

Other features include Golang dependency analysis, operating system package
discovery in container images and full `.gitignore` support when scanning git
repositories.

`bom` can also be used as a Go library: see
[Using bom as a library](#using-bom-as-a-library).

For more in-depth instructions on how to create an SBOM for your project, see
["Generating a Bill of Materials for Your Project"](https://kubernetes-sigs.github.io/bom/tutorials/creating_bill_of_materials/).

The guide includes information about what a Software Bill of Materials is,
the SPDX standard, and instructions to add files, images, directories, and
other sources to your SBOM.

- [Installation](#installation)
- [Usage](#usage)
  - [`bom generate`](#bom-generate)
  - [`bom document`](#bom-document)
  - [`bom validate`](#bom-validate)
- [Examples](#examples)
  - [Generate a SBOM from the Current Directory](#generate-a-sbom-from-the-current-directory)
  - [Process a Container Image](#process-a-container-image)
  - [Generate a SBOM to describe files](#generate-a-sbom-to-describe-files)
- [Using bom as a library](#using-bom-as-a-library)
- [Code of conduct](#code-of-conduct)

## Installation

To install `bom`:

```console
go install sigs.k8s.io/bom/cmd/bom@latest
```

## Usage

- completion: generate the autocompletion script for the specified shell
- [document](#bom-document): Work with SPDX documents
- [generate](#bom-generate): Create SPDX manifests
- [validate](#bom-validate): Check artifacts against an SBOM
- help: Help about any command
- version: Print the version

### `bom generate`

`bom generate` is the `bom` subcommand to generate SPDX manifests.

Currently supports creating SBOM from directories, files, images,
archives and docker archives (images in tarballs). It supports pulling
images from remote registries for analysis.

The operating system packages installed in images (Alpine, Debian and
RPM based distributions) are listed in the SBOM, together with the
image layers. Directories are scanned for the codebases they hold, like
Go modules, whose dependencies are resolved and listed with their
licenses.

Go binaries found in images and in files passed with --file are
listed with the Go modules they were built from, as recorded in
their embedded build information.

The SBOM data can also be exported to an in-toto provenance
attestation. The output will produce a provenance statement listing all
the SPDX data as in-toto subjects, but otherwise ready to be
completed by a later stage in your CI/CD pipeline. See the
--provenance flag for more details.

```console
Usage:
  bom generate [flags]

Flags:
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

Global Flags:
      --log-level string   the logging verbosity, either 'panic', 'fatal', 'error', 'warning', 'info', 'debug', 'trace' (default "info")

```

Directories are scanned honoring the `.gitignore` files they contain. The
`--ignore` flag adds more patterns, written in the same gitignore syntax (for
example `--ignore '*.log' --ignore 'testdata/'`), and `--no-gitignore` stops
bom from reading the `.gitignore` files.

### `bom document`

The `bom document subcommand` can visualize SBOMs as well as query them for
information.

```console
bom document → Work with SPDX documents

Usage:
  bom document [command]

Available Commands:
  dot         bom document dot → Export the SBOM graph in Graphviz DOT format
  outline     bom document outline → Draw structure of a SPDX document
  query       bom document query → Search for information in an SBOM
```

### `bom document outline`

Using `bom document outline` SBOM contents can be rendered to see how the
information they contain is structured. Here is an example rendering the
`debian:bookworm-slim` image for amd64:

```
bom generate --name debian --output=debian.spdx.json --image \
  debian@sha256:0aac521df91463e54189d82fe820b6d36b4a0992751c8339fbdd42e2bc1aa491

bom document outline debian.spdx.json

               _
 ___ _ __   __| |_  __
/ __| '_ \ / _` \ \/ /
\__ \ |_) | (_| |>  <
|___/ .__/ \__,_/_/\_\
    |_|

 📂 SPDX Document debian
  │
  │ 📦 DESCRIBES 1 Packages
  │
  ├ debian@sha256:0aac521df91463e54189d82fe820b6d36b4a0992751c8339fbdd42e2bc1aa491
  │  │ 🔗 88 Relationships
  │  ├ CONTAINS PACKAGE apt@2.5.4
  │  ├ CONTAINS PACKAGE base-files@12.3
  │  ├ CONTAINS PACKAGE base-passwd@3.6.1
  │  ├ CONTAINS PACKAGE bash@5.2.15-2
  │  ├ CONTAINS PACKAGE bsdutils@1:2.38.1-4
  │  ├ CONTAINS PACKAGE coreutils@9.1-1
  │  ├ CONTAINS PACKAGE dash@0.5.11+git20210903+057cd650a4ed-9
  │  ├ CONTAINS PACKAGE debconf@1.5.81
  │  ├ CONTAINS PACKAGE debian-archive-keyring@2021.1.1
  │  ├ CONTAINS PACKAGE debianutils@5.7-0.4

[trimmed]

  │  ├ CONTAINS PACKAGE sha256:79356561b2368d4930234f8f5bb82fcc280504cd9f21cd0b1a423599b32f4de9

[trimmed]

```

Use `--purl` to label packages with their package URLs, `--depth` to limit how
deep the tree is drawn and `--find` to draw only the branches leading to a
package, which shows where it comes from.

### `bom document query`

`bom document query` searches an SBOM for elements matching a set of filters
by depth, name or package URL. For example, to list the Go modules hosted on
GitHub that a project depends on:

```
bom document query sbom.spdx.json 'purl:pkg:golang/github.com/*'
```

### `bom document dot`

`bom document dot` writes the relationship graph of an SBOM in the
[DOT language](https://graphviz.org/doc/info/lang.html), which Graphviz and
other tools can render. Unlike the outline, each element appears only once,
even when several others relate to it, and every edge is labelled with its
SPDX relationship types:

```
bom document dot debian.spdx.json | dot -Tsvg > debian.svg
```

Use `--root` to render only the graph reachable from one element, `--depth` to
limit how many relationship steps are followed and `--no-files` to leave file
elements out.

### `bom validate`

`bom validate` checks files against the checksums an SBOM records for them.
With `--dir`, every file in a directory is checked against the package
describing it:

```
bom validate sbom.spdx.json --dir .
```

## Examples

The following examples show how bom can process different sources to generate
an SPDX Bill of Materials. Multiple sources can be combined to get a document
describing different packages.

### Generate a SBOM from the Current Directory

To process a directory as a source for your SBOM, use the `-d` flag or simply pass
the path (or current dir) as the first argument to `bom generate`:

```console
$ bom generate --name hello --output hello.spdx.json .
$ bom document outline hello.spdx.json

[...]

 📂 SPDX Document hello
  │
  │ 📦 DESCRIBES 1 Packages
  │
  ├ example.com/hello
  │  │ 🔗 5 Relationships
  │  ├ DEPENDS_ON PACKAGE github.com/google/uuid@v1.6.0
  │  ├ DEPENDS_ON PACKAGE stdlib@1.24
  │  ├ CONTAINS FILE go.mod (go.mod)
  │  ├ CONTAINS FILE go.sum (go.sum)
  │  └ CONTAINS FILE main.go (main.go)
  │
  └ 📄 DESCRIBES 0 Files
```

A directory holding a Go module is described by a package named after the
module path, which depends on the modules the code requires. The licenses of
those modules are looked up online and recorded as their declared license; with
`--offline`, bom does not reach the network and only reads the dependency data
available locally.

### Process a Container Image

This example pulls the `kube-apiserver` image, analyzes it, and describes it in
the SBOM. The operating system packages found in the image and its layers are
listed in the resulting document, and the Go binaries in the image
(`kube-apiserver` and `go-runner`) are listed with the Go modules they depend
on:

```console
bom generate -n http://example.com/ --output kube-apiserver.spdx.json \
  --image registry.k8s.io/kube-apiserver:v1.34.0
```

### Generate a SBOM to describe files

You can create an SBOM with just files in the manifest. For that, use `-f`.
Files that are Go binaries are listed with the Go modules they were built from:

```console
bom generate -n http://example.com/ --output files.spdx.json \
  -f Makefile \
  -f file1.exe \
  -f document.md \
  -f other/file.txt
```

## Using bom as a library

The `sigs.k8s.io/bom/pkg/bom` package generates, reads and writes SBOMs as
[protobom](https://github.com/protobom/protobom) documents, a format-neutral
model that protobom can also serialize to other SPDX and CycloneDX formats:

```go
doc, err := bom.Generate(ctx, &bom.GenerateOptions{
    Name:        "my-project",
    Directories: []string{"."},
})
if err != nil {
    return err
}
return bom.Write(os.Stdout, doc, &bom.WriteOptions{Format: bom.FormatJSON})
```

The object model in `sigs.k8s.io/bom/pkg/spdx` is deprecated. See the
[migration guide](https://kubernetes-sigs.github.io/bom/tutorials/migrating_to_pkg_bom/)
for how to move to `pkg/bom` and for the changes in v0.8.0 that affect library
users and the generated SBOMs.

## Code of conduct

Participation in the Kubernetes community is governed by the [Kubernetes Code of Conduct](code-of-conduct.md).


| | | |
| --- | --- | -- |
| ![ACT TAC](logo/act-tac.png) |  ![SPDX](logo/spdx.png) | ![Kubernetes](logo/kubernetes.png) |
