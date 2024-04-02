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
[Automating Compliance Tooling TAC](https://github.com/act-project/TAC)

[![terminal demo](https://asciinema.org/a/418528.svg)](https://asciinema.org/a/418528?autoplay=1)

`bom` is a general-purpose tool that can generate SPDX packages from
directories, container images, single files, and other sources. The utility
has a built-in license classifier that recognizes the 400+ licenses in
the SPDX catalog.

Other features include Golang dependency analysis and full `.gitignore`
support when scanning git repositories.

For more in-depth instructions on how to create an SBOM for your project, see
["Generating a Bill of Materials for Your Project"](https://kubernetes-sigs.github.io/bom/tutorials/creating_bill_of_materials/).

The guide includes information about what a Software Bill of Materials is,
the SPDX standard, and instructions to add files, images, directories, and
other sources to your SBOM.

- [Installation](#installation)
- [Usage](#usage)
  - [`bom generate`](#bom-generate)
  - [`bom document`](#bom-document)
- [Examples](#examples)
  - [Generate a SBOM from the Current Directory](#generate-a-sbom-from-the-current-directory)
  - [Process a Container Image](#process-a-container-image)
  - [Generate a SBOM to describe files](#generate-a-sbom-to-describe-files)
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
- help: Help about any command

### `bom generate`

`bom generate` is the `bom` subcommand to generate SPDX manifests.

Currently supports creating SBOM from files, images, and docker
archives (images in tarballs). It supports pulling images from
remote registries for analysis.

bom can take a deeper look into images using a growing number
of analyzers designed to add more sense to common base images.

The SBOM data can also be exported to an in-toto provenance
attestation. The output will produce a provenance statement listing all
the SPDX data as in-toto subjects, but otherwise ready to be
completed by a later stage in your CI/CD pipeline. See the
--provenance flag for more details.

```console
Usage:
  bom generate [flags]

Flags:
  -a, --analyze-images          go deeper into images using the available analyzers
      --archive strings         list of archives to add as packages (supports tar, tar.gz)
  -c, --config string           path to yaml SBOM configuration file
  -d, --dirs strings            list of directories to include in the manifest as packages
  -f, --file strings            list of files to include
      --format string           format of the document (supports tag-value, json) (default "tag-value")
  -h, --help                    help for generate
      --ignore strings          list of regexp patterns to ignore when scanning directories
  -i, --image strings           list of images
      --image-archive strings   list of docker archive tarballs to include in the manifest
  -l, --license string          SPDX license identifier to declare in the SBOM
      --name string             name for the document, in contrast to URLs, intended for humans
  -n, --namespace string        an URI that serves as namespace for the SPDX doc
      --no-gitignore            don't use exclusions from .gitignore files
      --no-gomod                don't perform go.mod analysis, sbom will not include data about go packages
      --no-transient            don't include transient go dependencies, only direct deps from go.mod
  -o, --output string           path to the file where the document will be written (defaults to STDOUT)
      --provenance string       path to export the SBOM as an in-toto provenance statement
      --scan-images             scan container images to look for OS information (currently debian only) (default true)

Global Flags:
      --log-level string   the logging verbosity, either 'panic', 'fatal', 'error', 'warning', 'info', 'debug', 'trace' (default "info")

```

### `bom document`

The `bom document subcommand` can visualize SBOMs as well as query them for
information.

```console
bom document → Work with SPDX documents

Usage:
  bom document [command]

Available Commands:
  outline     bom document outline → Draw structure of a SPDX document
  query       bom document query → Search for information in an SBOM
```

### `bom document outline`

Using `bom document outline` SBOM contents can be rendered too see how the
information they contain is structured. Here is an example rendering the
`debian:bookworm-slim` image for amd64:

```
bom generate --output=debian.spdx --image \
  debian@sha256:0aac521df91463e54189d82fe820b6d36b4a0992751c8339fbdd42e2bc1aa491 | bom document outline -

bom document outline debian.spdx

               _      
 ___ _ __   __| |_  __
/ __| '_ \ / _` \ \/ /
\__ \ |_) | (_| |>  < 
|___/ .__/ \__,_/_/\_\
    |_|               

 📂 SPDX Document SBOM-SPDX-71f1009c-dc17-4f4d-b4ec-72210c1a8d7f
  │ 
  │ 📦 DESCRIBES 1 Packages
  │ 
  ├ sha256:0aac521df91463e54189d82fe820b6d36b4a0992751c8339fbdd42e2bc1aa491
  │  │ 🔗 1 Relationships
  │  └ CONTAINS PACKAGE sha256:b37cbf60a964400132f658413bf66b67e5e67da35b9c080be137ff3c37cc7f65
  │  │  │ 🔗 86 Relationships
  │  │  ├ CONTAINS PACKAGE apt@2.5.4
  │  │  ├ CONTAINS PACKAGE base-files@12.3
  │  │  ├ CONTAINS PACKAGE base-passwd@3.6.1
  │  │  ├ CONTAINS PACKAGE bash@5.2.15-2
  │  │  ├ CONTAINS PACKAGE bsdutils@1:2.38.1-4
  │  │  ├ CONTAINS PACKAGE coreutils@9.1-1
  │  │  ├ CONTAINS PACKAGE dash@0.5.11+git20210903+057cd650a4ed-9
  │  │  ├ CONTAINS PACKAGE debconf@1.5.81
  │  │  ├ CONTAINS PACKAGE debian-archive-keyring@2021.1.1
  │  │  ├ CONTAINS PACKAGE debianutils@5.7-0.4
  │  │  ├ CONTAINS PACKAGE diffutils@1:3.8-3
  │  │  ├ CONTAINS PACKAGE dpkg@1.21.13
  │  │  ├ CONTAINS PACKAGE e2fsprogs@1.46.6~rc1-1+b1
  │  │  ├ CONTAINS PACKAGE findutils@4.9.0-3
  │  │  ├ CONTAINS PACKAGE gcc-12-base@12.2.0-13
  │  │  ├ CONTAINS PACKAGE gpgv@2.2.40-1
  │  │  ├ CONTAINS PACKAGE grep@3.8-3
  │  │  ├ CONTAINS PACKAGE gzip@1.12-1
  │  │  ├ CONTAINS PACKAGE hostname@3.23+nmu1
  │  │  ├ CONTAINS PACKAGE init-system-helpers@1.65.2

[trimmed]

```

## Examples

The following examples show how bom can process different sources to generate
an SPDX Bill of Materials. Multiple sources can be combined to get a document
describing different packages.

### Generate a SBOM from the Current Directory

To process a directory as a source for your SBOM, use the `-d` flag or simply pass
the path (or current dir) as the first argument to `bom generate`:

```bash
bom generate .
```

### Process a Container Image

This example pulls the `kube-apiserver` image, analyzes it, and describes in the
SBOM. Each of its layers are then expressed as a subpackage in the resulting
document:

```console
bom generate -n http://example.com/ --image registry.k8s.io/kube-apiserver:v1.21.0
```

### Generate a SBOM to describe files

You can create an SBOM with just files in the manifest. For that, use `-f`:

```console
bom generate -n http://example.com/ \
  -f Makefile \
  -f file1.exe \
  -f document.md \
  -f other/file.txt
```

## Code of conduct

Participation in the Kubernetes community is governed by the [Kubernetes Code of Conduct](code-of-conduct.md).


| | | |
| --- | --- | -- |
| ![ACT TAC](logo/act-tac.png) |  ![SPDX](logo/spdx.png) | ![Kubernetes](logo/kubernetes.png) |
