# bom (Bill of Materials)

Create SPDX compliant Bill of Materials

- [Summary](#summary)
- [Installation](#installation)
- [Usage](#usage)
  - [Available Commands](#available-commands)
  - [Command line flags](#command-line-flags)
- [Generate your own Bill of Materials](#generate-your-own-bill-of-materials)
- [Examples](#examples)
  - [Generate an SBOM from the Current Directory](#generate-an-sbom-from-the-current-directory)
  - [Process a Container Image](#process-a-container-image)
  - [Generate a BOM to describe files](#generate-a-bom-to-describe-files)
- [Community, discussion, contribution, and support](#community-discussion-contribution-and-support)
  - [Code of conduct](#code-of-conduct)

## Summary

bom is a little utility that lets software authors generate
SPDX manifests to describe the contents of a release. The
SPDX manifests provide a way to list and verify all items
contained in packages, images, and individual files while
packing the data along with licensing information.

bom is still in its early stages and it is an effort to open
the libraries developed for the Kubernetes SBOM for other
projects to use.

For a more in depth instructions on how to create an SBOM see
[Generating a Bill of Materials for Your Project](create-a-bill-of-materials.md)

---

`bom generate` is the subcommand to generate SPDX manifests.
Currently supports creating SBOM for files, images, and docker
archives (images in tarballs). Supports pulling images from
registries.

`bom` can take a deeper look into images using a growing number
of analyzers designed to add more sense to common base images.

## Installation

To use bom generate, compile the release engineering tools:

```console
git clone git@github.com:kubernetes/release.git
cd release
./compile-release-tools bom
```

## Usage

```console
  bom [subcommand]
```

### Available Commands

```console
  generate    bom generate → Create SPDX manifests
  help        Help about any command
```

### Command line flags

```console
Flags:
  -a, --analyze-images     go deeper into images using the available analyzers
  -c, --config string      path to yaml SBOM configuration file
  -d, --dirs strings       list of directories to include in the manifest as packages
  -f, --file strings       list of files to include
  -h, --help               help for generate
      --ignore strings     list of regexp patterns to ignore when scanning directories
  -i, --image strings      list of images
  -n, --namespace string   an URI that servers as namespace for the SPDX doc
      --no-gitignore       don't use exclusions from .gitignore files
      --no-gomod           don't perform go.mod analysis, sbom will not include data about go packages
      --no-transient       don't include transient go dependencies, only direct deps from go.mod
  -o, --output string      path to the file where the document will be written (defaults to STDOUT)
  -t, --tarball strings    list of docker archive tarballs to include in the manifest
```

---

`bom` is a tiny utility that leverages the code written for the Kubernetes
Bill of Materials project. It enables software authors to generate an
SBOM for their projects in a simple, yet powerful way.

![terminal demo](../../docs/bom/cast.svg "Terminal demo")

`bom` is a general-purpose tool that can generate SPDX packages from
directories, container images, single files, and other sources. The utility
has a built-in license classifier that recognizes the 400+ licenses in
the SPDX catalog.

Other features include Golang dependency analysis and full `.gitignore`
support when scanning git repositories.

## Generate your own Bill of Materials

If you are looking for a way to create a bill of materials for your project, we
have created a
[HOWTO guide to generating an SBOM](../../docs/bom/create-a-bill-of-materials.md).

The guide includes information about
[what a Bill of Materials is](../../docs/bom/create-a-bill-of-materials.md#what-is-a-bill-of-materials),
[the SPDX standard](../../docs/bom/create-a-bill-of-materials.md#spdx-software-package-data-exchange),
and instructions to add files, images, directories, and
other sources to your BOM.

## Examples

The following examples show how bom can process different sources to generate
an SPDX Bill of Materials. Multiple sources can be combined to get a document
describing different packages.

### Generate an SBOM from the Current Directory

To process a directory as a source for your SBOM, use the `-d` flag or simply pass
the path as the first argument to `bom`:

```bash
bom generate -n http://example.com/ .
```

### Process a Container Image

This example pulls the kube-apiserver image, analyzes it, and describes in the
SBOM. Each of its layers are then expressed as a subpackage in the resulting
document:

```console
bom generate -n http://example.com/ --image k8s.gcr.io/kube-apiserver:v1.21.0 
```

### Generate a BOM to describe files

You can create an SBOM with just files in the manifest. For that, use `-f`:

```console
bom generate -n http://example.com/ \
  -f Makefile \
  -f file1.exe \
  -f document.md \
  -f other/file.txt 
```

---

## Community, discussion, contribution, and support

Learn how to engage with the Kubernetes community on the [community page](http://kubernetes.io/community/).

You can reach the maintainers of this project at:

- [Slack](http://slack.k8s.io/)
- [Mailing List](https://groups.google.com/forum/#!forum/kubernetes-dev)

### Code of conduct

Participation in the Kubernetes community is governed by the [Kubernetes Code of Conduct](code-of-conduct.md).
