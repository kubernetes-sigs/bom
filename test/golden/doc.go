/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package golden snapshots the output of the SBOM generation pipeline.
//
// The tests in this package run the public DocBuilder API against small,
// hermetic fixtures (a dependency-free Go module, a synthetic Debian image
// archive and a plain file) and compare the serialized documents against
// golden files in testdata/golden. Their purpose is to make any change to
// the generated output an explicit, reviewable diff — especially during
// the migration of the generation engine to a protobom-based
// implementation.
//
// Outputs are canonicalized before comparison (see golden_test.go):
// blocks and arrays are sorted and unstable data such as timestamps and
// temp paths are pinned, because parts of the pipeline emit elements in
// nondeterministic order.
//
// To regenerate the golden files after an intentional change:
//
//	go test ./test/golden -update
package golden
