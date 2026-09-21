---
title: "Migrating to bom v0.8"
linkTitle: "Migrating to bom v0.8"
tags: ["tutorial", "reference"]
date: 2026-09-21
description: Moving library code to pkg/bom and what changes in the SBOMs bom generates

---

bom v0.8.0 rebuilds SBOM generation and parsing on
[protobom](https://github.com/protobom/protobom), a format-neutral SBOM model,
and on [unpack](https://github.com/carabiner-dev/unpack), which discovers the
packages in directories, images and archives. This page is for Go programs using
bom as a library and for anyone consuming the SBOMs it generates.

## The new library API: `pkg/bom`

`sigs.k8s.io/bom/pkg/bom` is the supported entry point for library users. It
works on protobom documents (`*sbom.Document` from
`github.com/protobom/protobom/pkg/sbom`):

| Function | What it does |
| --- | --- |
| `bom.Generate(ctx, *bom.GenerateOptions)` | Scans directories, images, image archives, archives and files into a new document |
| `bom.Open(path)` | Reads an SBOM from a file, an http(s) URL or STDIN (`-` or an empty path) |
| `bom.Parse(io.Reader)` | Reads an SBOM from a reader |
| `bom.Write(io.Writer, doc, *bom.WriteOptions)` | Renders a document as SPDX 2.3 JSON or tag-value, like `bom generate` does (without the trailing newline `bom generate` adds on STDOUT) |

A complete program generating an SBOM for the current directory:

```go
package main

import (
	"context"
	"os"

	"sigs.k8s.io/bom/pkg/bom"
)

func main() {
	doc, err := bom.Generate(context.Background(), &bom.GenerateOptions{
		Name:        "my-project",
		Namespace:   "https://example.com/my-project",
		Directories: []string{"."},
	})
	if err != nil {
		panic(err)
	}
	if err := bom.Write(os.Stdout, doc, &bom.WriteOptions{Format: bom.FormatJSON}); err != nil {
		panic(err)
	}
}
```

`bom.Open` and `bom.Parse` read every format protobom supports: SPDX 2.2 and
2.3 in JSON and tag-value, SPDX 3, and CycloneDX. SPDX 2.1 documents are read
like SPDX 2.2 ones. Since the documents are protobom documents, they can also
be written with protobom's own writer (`github.com/protobom/protobom/pkg/writer`)
to any of the formats it supports, CycloneDX included. `bom.Write` exists for the output `bom generate` writes.
It keeps the creators a document names, and declares the license list version
of `WriteOptions.LicenseListVersion` (bom's own list when empty): protobom does
not keep the version a document read with `bom.Open` declared.

## Moving off `pkg/spdx`

The object model in `sigs.k8s.io/bom/pkg/spdx` (`Document`, `Package`, `File`
and friends) remains as a compatibility layer, but its entry points are
deprecated and may be removed in a future major version. `pkg/serialize`, which
renders that model, stays for the same purpose; new code should use
`bom.Write`:

| Before | Now |
| --- | --- |
| `spdx.NewDocBuilder().Generate(opts)` | `bom.Generate(ctx, opts)`, then `bom.Write` to render SPDX |
| `spdx.OpenDoc(path)` | `bom.Open(path)`; convert with `spdx.FromProtobom` where the legacy model is still needed |
| `serialize.JSON{}.Serialize(doc)`, `serialize.TagValue{}.Serialize(doc)` | `bom.Write(w, doc, &bom.WriteOptions{Format: ...})` |
| `(*spdx.SPDX).PackageFromDirectory`, `PackageFromImageTarball`, `PackageFromArchive`, `ImageRefToPackage` and the other package builders | `bom.Generate` with the matching `GenerateOptions` field |
| The image analyzers, the Go module scanner (`spdx.GoModule` and related) and `pkg/osinfo` | Nothing: discovery is done by unpack inside `bom.Generate` |
| `(*license.ReaderDefaultImpl).Classifier()`, `(*license.ReaderDefaultImpl).Catalog()` | Nothing: both return `nil` now; use `license.NewCatalogWithOptions` for the SPDX license list |

`spdx.FromProtobom` and `spdx.ToProtobom` convert between the two models, so
code can move one call site at a time.

`spdx.DocGenerateOptions` maps onto `bom.GenerateOptions` as follows:

| `spdx.DocGenerateOptions` | `bom.GenerateOptions` |
| --- | --- |
| `Name`, `Namespace`, `CreatorPerson` | same names |
| `Directories`, `Images`, `Archives`, `Files` | same names |
| `Tarballs` | `ImageArchives` |
| `IgnorePatterns` | `IgnorePatterns` (gitignore syntax, as before: only the `--ignore` help text of v0.7.1 called them regular expressions) |
| `NoGitignore`, `OnlyDirectDeps`, `Offline` | same names |
| `ProcessGoModules` | `NoDependencies`, inverted: `ProcessGoModules: false` is `NoDependencies: true` |
| `LicenseListVersion` | `bom.WriteOptions.LicenseListVersion`, a release like `v3.28.0` (`latest` is rejected) |
| `ScanImages`, `ScanLicenses` | always on |
| `AnalyseLayers`, `License` | no longer supported |
| `ConfigFile`, `ExternalDocumentRef` | CLI only (`bom generate --config`) |

## API changes since v0.7.1

Besides the deprecations, these exported APIs changed incompatibly:

- `pkg/query`: filters work on protobom nodes. `Engine.Document` is a
  `*sbom.Document`, `FilterResults.Objects` a `map[string]*sbom.Node`, and
  `Filter.Apply`, `ObjectCycler.Cycle` and `ObjectCycler.CycleFull` take the
  `*query.Graph` of the document to walk its relationships. `MatcherFunction`
  receives a `*sbom.Node`.
- `pkg/provenance`: statements are built on the in-toto attestation v1 types
  (`github.com/in-toto/attestation/go/v1`). `Statement` embeds the attestation
  `v1.Statement` instead of `StatementHeader`, which is gone. Subjects and
  materials are `*v1.ResourceDescriptor` values, so
  `StatementImplementation.SubjectFromFile` returns one and `VerifySubjects`
  takes a `[]*v1.ResourceDescriptor`, and `NewSLSAPredicate` returns a
  pointer. The SLSA 0.2 fields (`Builder`, `BuildType`, `Invocation`,
  `Materials`, ...) moved from `Predicate` into its `PredicateContent`, a
  `*provenance/v02.Provenance` from the attestation module, with
  `GetBuilder`, `GetMaterials`, `SetBuilderID` and `AddMaterial` as helpers;
  `Predicate.Metadata` and `Predicate.BuildConfig` are gone with them.
  `PredicateImplementation` and `(*Predicate).SetImplementation` are removed,
  and in `provenancefakes` `FakePredicateImplementation` is removed and
  `FakeStatementImplementation` follows the new signatures.
- `pkg/spdx`: `spdx.Object.ToProvenanceSubject` and
  `(*spdx.Entity).ToProvenanceSubject` return a `*v1.ResourceDescriptor`.
  `DocBuilderImplementation` lost `CreateDocument`, `CreateSPDXClient` and its
  per-source scanning methods (`ScanDirectories`, `ScanImages`, ...) in favor
  of `GenerateDocument`.
- `cmd/bom/cmd`: the query printers receive protobom nodes. This package is the
  CLI's implementation and is not meant to be imported.

## Changes in the generated SBOMs

The new engine describes the same sources differently in places. Consumers
comparing SBOMs across the upgrade will notice:

- **Default format.** `bom generate` writes SPDX JSON unless `--format
  tag-value` is passed. v0.7.1 defaulted to tag-value.
- **Go module packages.** Unless `--no-gomod` is passed, a directory holding a
  Go module is described by a package named after the module path
  (`sigs.k8s.io/bom` instead of `bom`), whose version is the tag checked out
  when `HEAD` is tagged and empty otherwise. Package identifiers
  follow the module path and version: `SPDXRef-Package-<module>-<version>`
  instead of `SPDXRef-Package-gomod-<module>-<version>`.
- **Go dependency licenses.** The licenses of Go dependencies are recorded in
  `licenseDeclared`, as what the module declares, instead of
  `licenseConcluded`. They are looked up online; with `--offline` bom does not
  reach the network and almost no dependency carries a license.
- **Images.** The operating system packages of an image and its layers are
  listed directly under the image package; layers are no longer packages
  holding the files and packages of each layer.
- **Retired flags.** `--analyze-images`, `--scan-images` and `--license` are
  accepted but have no effect; bom warns when they ask for something it no
  longer does. OS package scanning is part of every run. `--license-list-version` only labels the document and has to name
  a release: `latest` is rejected.
- **Stricter parsing.** Documents are validated against the SPDX schema when
  read. Documents with the violations bom used to read through (a missing
  `spdxVersion`, element identifiers without the `SPDXRef-` prefix, free-form
  package originators or suppliers in JSON) are repaired with a warning;
  others are rejected with the parser's error.
- **License reader.** `license.Reader.LicenseFromFile` and `LicenseFromLabel`
  return only the license ID and name; the other fields of `license.License`
  (license text, reference URLs, ...) are empty.
