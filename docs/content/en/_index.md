
---
title: "Documentation"
linkTitle: "Documentation"
type: "docs"
tags: ["intro"]
weight: 20

cascade:
- _target:
    path: "/blog/**"
  type: "blog"
  # set to false to include a blog section in the section nav along with docs
  toc_root: true
- _target:
    path: "/**"
    kind: "page"
  type: "docs"
- _target:
    path: "/**"
    kind: "section"
  type: "docs"
- _target:
    path: "/**"
    kind: "section"
  type: "home"
---

bom is a utility that leverages the code written for the Kubernetes Bill of Materials project. It enables software authors to generate an SBOM for their projects in a simple, yet powerful way.

bom is a general-purpose tool that can generate SPDX packages from directories, container images, single files, and other sources. The utility has a built-in license classifier that recognizes the 400+ licenses in the SPDX catalog.
