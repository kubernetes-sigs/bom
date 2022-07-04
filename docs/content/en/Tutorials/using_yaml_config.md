---
title: "Configuring BOM via YAML"
linkTitle: "Configuring BOM via YAML"
tags: ["tutorial", "reference"]
date: 2022-06-27
description: Configure BOM via YAML

---

## Usage:

bom can be configured via a YAML file. The usage is as:

```shell
bom generate -c path/to/yaml/config
```

## Config:

The YAML config looks like:

```yaml
namespace: https://example.com/  # an URI that serves as namespace for the SPDX doc
license: Apache-2.0 # SPDX license identifier to declare in the SBOM
name: ExampleBOM  #name for the document, in contrast to URLs, intended for humans
creator:
 person: Author Name (email@example.com)
 tool: bom 

artifacts:
    - type: directory # Valid choices are "directory" or "file" or "image"
      source: ./bom # Path to container in registry if type is "image" else path to directory or file
      license: Apache-2.0 # SPDX identifier of the license
      gomodules: true # Boolean. Set it to true if this artifact is a gomodule.

    - type: image # Valid choices are "directory" or "file" or "image"
      source: ghcr.io/myorg/myrepo/myimage:tag # Path to container in registry if type is "image" else path to directory or file
      license: Apache-2.0 # SPDX identifier of the license

    - type: file # Valid choices are "directory" or "file" or "image"
      source: ./demo.py # Path to container in registry if type is "image" else path to directory or file
      license: Apache-2.0 # SPDX identifier of the license

```

### `namespace`:

A URI that serves as namespace for the SPDX doc. This is used as value for `DocumentNamespace` in the generated SPDX BOM.

### `license`:

This is a SPDX license identifier. It's top level for the whole generated SBOM.

### `name`:

Name of the generated BOM. Intended for humans.

### `creator` :

Information about BOM creator.

#### `person` :

Name of person who created the BOM.

#### `tool` :

Tool used for creating the BOM.

### `artifacts` :

#### `type` :

Type of artifact. Can be either "image" or "file" or "directory" . 

#### `source` :

Path to artifact. 

If artifact type is file, then `source` should be a path to the file.

If artifact type is directory, then `source` should be a path to the directory.

If artifact type is image, then `source` should be a path to the URI of image in container registry.

#### `license` :

Top level SPDX identifier of this artifact.

#### `gomodules` : 

This is a boolean. If set to true, then bom will assume the artifact to be a go module. The dependencies will also be scanned.

