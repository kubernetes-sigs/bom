---
title: "Quick Start"
linkTitle: "Quick Start"
weight: 1
tags: ["intro"]
---

## Installation

### Using binary:

You can see releases of `bom` on [Github Releases](https://github.com/kubernetes-sigs/bom/releases/). 

Replace the tag, os and architecture as required for below commands to install.

```console
curl -L https://github.com/kubernetes-sigs/bom/releases/download/v0.6.0/bom-amd64-linux -o bom
sudo install bom /usr/local/bin/
```

### Using go:

```console
go install sigs.k8s.io/bom/cmd/bom@latest
```


## Examples

The following examples show how bom can process different sources to generate
an SPDX Bill of Materials. Multiple sources can be combined to get a document
describing different packages.

### Generate a SBOM from the Current Directory

To process a directory as a source for your SBOM, use the `-d` flag or simply pass
the path as the first argument to `bom`:

```bash
bom generate -n http://example.com/ --output sbom.spdx.json .
```

### Process a Container Image

This example pulls the `kube-apiserver` image, analyzes it, and describes it in
the SBOM. The operating system packages found in the image and its layers are
listed in the resulting document, and the Go binaries in the image are listed
with the Go modules they were built from:

```console
bom generate -n http://example.com/ --output kube-apiserver.spdx.json \
  --image registry.k8s.io/kube-apiserver:v1.34.0
```

### Generate a SBOM to describe files

You can create an SBOM with just files in the manifest. For that, use `-f`:

```console
bom generate -n http://example.com/ --output files.spdx.json \
  -f Makefile \
  -f file1.exe \
  -f document.md \
  -f other/file.txt
```

## Code of conduct

Participation in the Kubernetes community is governed by the [Kubernetes Code of Conduct](code-of-conduct.md).
