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

package spdx

import (
	"errors"
	"slices"
	"strings"

	protospdx "github.com/protobom/protobom/pkg/formats/spdx"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ToProtobom converts a document in bom's legacy SPDX model to a
// protobom document, the inverse of FromProtobom.
//
// The document's top-level packages and files become root elements and
// the relationship graph is walked breadth-first from them, turning
// every reachable object into a node and every relationship into an
// edge. Objects are deduplicated by their SPDX identifier (with the
// SPDXRef- prefix stripped, the form protobom uses), so shared peers
// convert once. Relationships to peers in external documents, and
// relationships whose peer has no identifier and no reference, are
// dropped: protobom edges cannot express them.
//
// Following protobom's unserializer conventions, NOASSERTION license
// values are dropped and license expressions are kept whole rather
// than split. Legacy data protobom cannot express is dropped: package
// verification codes, licenses found in files at the package level,
// FilesAnalyzed, the document license list version, and relationship
// comments.
func ToProtobom(doc *Document) (*sbom.Document, error) {
	if doc == nil {
		return nil, errors.New("document is nil")
	}

	pdoc := sbom.NewDocument()
	md := pdoc.GetMetadata()
	md.Name = doc.Name
	if doc.Namespace != "" {
		docID := doc.ID
		if docID == "" {
			docID = "SPDXRef-DOCUMENT"
		}
		md.Id = doc.Namespace + "#" + docID
	}
	if !doc.Created.IsZero() {
		md.Date = timestamppb.New(doc.Created)
	}
	authors := []*sbom.Person{}
	if doc.Creator.Person != "" {
		authors = append(authors, personFromActor(doc.Creator.Person, false))
	}
	if doc.Creator.Organization != "" {
		authors = append(authors, personFromActor(doc.Creator.Organization, true))
	}
	md.Authors = authors
	tools := []*sbom.Tool{}
	for _, tool := range doc.Creator.Tool {
		tools = append(tools, &sbom.Tool{Name: tool})
	}
	md.Tools = tools

	// Walk the object graph breadth-first from the document roots,
	// converting each object once, keyed by its protobom identifier.
	visited := map[string]bool{}
	queue := []Object{}
	add := func(obj Object) {
		id := protobomID(obj.SPDXID())
		if id == "" || visited[id] {
			return
		}
		visited[id] = true
		queue = append(queue, obj)
		pdoc.GetNodeList().AddNode(objectToNode(obj))
	}

	roots := []string{}
	for _, key := range sortedKeys(doc.Packages) {
		add(doc.Packages[key])
		roots = append(roots, protobomID(key))
	}
	for _, key := range sortedKeys(doc.Files) {
		add(doc.Files[key])
		roots = append(roots, protobomID(key))
	}
	pdoc.GetNodeList().RootElements = roots

	for len(queue) > 0 {
		obj := queue[0]
		queue = queue[1:]
		fromID := protobomID(obj.SPDXID())
		for _, rel := range *obj.GetRelationships() {
			if rel.PeerExtReference != "" {
				continue
			}
			peerID := ""
			if rel.Peer != nil {
				peerID = protobomID(rel.Peer.SPDXID())
				if peerID != "" {
					add(rel.Peer)
				}
			}
			if peerID == "" {
				peerID = protobomID(rel.PeerReference)
			}
			if peerID == "" {
				continue
			}
			pdoc.GetNodeList().AddEdge(&sbom.Edge{
				Type: relationshipEdgeTypes[rel.Type],
				From: fromID,
				To:   []string{peerID},
			})
		}
	}

	return pdoc, nil
}

// protobomID strips the SPDXRef- prefix from a legacy identifier,
// yielding the form protobom stores; FromProtobom's spdxID inverts it.
func protobomID(id string) string {
	return strings.TrimPrefix(id, "SPDXRef-")
}

func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func objectToNode(obj Object) *sbom.Node {
	switch typed := obj.(type) {
	case *Package:
		return packageToNode(typed)
	case *File:
		return fileToNode(typed)
	}
	return nil
}

func packageToNode(p *Package) *sbom.Node {
	n := &sbom.Node{
		Id:               protobomID(p.SPDXID()),
		Type:             sbom.Node_PACKAGE,
		Name:             p.Name,
		Version:          p.Version,
		FileName:         p.FileName,
		UrlHome:          p.HomePage,
		UrlDownload:      p.DownloadLocation,
		LicenseConcluded: licenseValue(p.LicenseConcluded),
		LicenseComments:  p.LicenseComments,
		Copyright:        p.CopyrightText,
		Comment:          p.Comment,
		Hashes:           hashesFromChecksums(p.Checksum),
		PrimaryPurpose:   purposeFromSPDX(p.PrimaryPurpose),
	}
	if declared := licenseValue(p.LicenseDeclared); declared != "" {
		n.Licenses = []string{declared}
	}
	n.Identifiers, n.ExternalReferences = referencesFromExternalRefs(p.ExternalRefs)
	if p.Supplier.Person != "" {
		n.Suppliers = append(n.Suppliers, personFromActor(p.Supplier.Person, false))
	}
	if p.Supplier.Organization != "" {
		n.Suppliers = append(n.Suppliers, personFromActor(p.Supplier.Organization, true))
	}
	if p.Originator.Person != "" {
		n.Originators = append(n.Originators, personFromActor(p.Originator.Person, false))
	}
	if p.Originator.Organization != "" {
		n.Originators = append(n.Originators, personFromActor(p.Originator.Organization, true))
	}
	return n
}

func fileToNode(f *File) *sbom.Node {
	n := &sbom.Node{
		Id:               protobomID(f.SPDXID()),
		Type:             sbom.Node_FILE,
		Name:             f.Name,
		FileName:         f.FileName,
		FileTypes:        f.FileType,
		LicenseConcluded: licenseValue(f.LicenseConcluded),
		LicenseComments:  f.LicenseComments,
		Copyright:        f.CopyrightText,
		Hashes:           hashesFromChecksums(f.Checksum),
	}
	if license := licenseValue(f.LicenseInfoInFile); license != "" {
		n.Licenses = []string{license}
	}
	return n
}

// licenseValue filters the SPDX no-claim marker, matching protobom's
// unserializer convention.
func licenseValue(license string) string {
	if license == NOASSERTION {
		return ""
	}
	return license
}

// personFromActor parses a legacy actor string ("Name (email)") into a
// protobom person.
func personFromActor(actor string, isOrg bool) *sbom.Person {
	_, name, email := protospdx.ParseActorString(actor)
	return &sbom.Person{Name: name, Email: email, IsOrg: isOrg}
}

// hashesFromChecksums converts the legacy algorithm-name keyed map to
// protobom's hash map, dropping algorithms protobom has no enum value
// for; the inverse of checksums.
func hashesFromChecksums(sums map[string]string) map[int32]string {
	if len(sums) == 0 {
		return nil
	}
	out := map[int32]string{}
	for name, value := range sums {
		if algo := sbom.HashAlgorithmFromSPDX(common.ChecksumAlgorithm(name)); algo != sbom.HashAlgorithm_UNKNOWN {
			out[int32(algo)] = value
		}
	}
	return out
}

// referencesFromExternalRefs splits legacy external references into
// protobom software identifiers and external references, the inverse
// of externalRefs.
func referencesFromExternalRefs(refs []ExternalRef) (map[int32]string, []*sbom.ExternalReference) {
	var identifiers map[int32]string
	var external []*sbom.ExternalReference
	for _, ref := range refs {
		if idType := sbom.SoftwareIdentifierTypeFromString(ref.Type); idType != sbom.SoftwareIdentifierType_UNKNOWN_IDENTIFIER_TYPE {
			if identifiers == nil {
				identifiers = map[int32]string{}
			}
			identifiers[int32(idType)] = ref.Locator
			continue
		}
		external = append(external, &sbom.ExternalReference{
			Url:  ref.Locator,
			Type: extRefTypeFromSPDX(ref.Type),
		})
	}
	return identifiers, external
}

// extRefTypeFromSPDX mirrors protobom's unserializer mapping of SPDX
// external reference types (extRefToProtobomEnum, unexported there).
func extRefTypeFromSPDX(refType string) sbom.ExternalReference_ExternalReferenceType {
	switch refType {
	case "bower":
		return sbom.ExternalReference_BOWER
	case "maven-central":
		return sbom.ExternalReference_MAVEN_CENTRAL
	case "npm":
		return sbom.ExternalReference_NPM
	case "nuget":
		return sbom.ExternalReference_NUGET
	case "advisory":
		return sbom.ExternalReference_SECURITY_ADVISORY
	case "fix":
		return sbom.ExternalReference_SECURITY_FIX
	case "swid":
		return sbom.ExternalReference_SECURITY_SWID
	case "url":
		return sbom.ExternalReference_SECURITY_OTHER
	default:
		return sbom.ExternalReference_OTHER
	}
}

// purposeFromSPDX maps an SPDX package purpose back to protobom's
// vocabulary, the inverse of primaryPurpose.
func purposeFromSPDX(purpose string) []sbom.Purpose {
	switch purpose {
	case purposeApplication:
		return []sbom.Purpose{sbom.Purpose_APPLICATION}
	case "FRAMEWORK":
		return []sbom.Purpose{sbom.Purpose_FRAMEWORK}
	case "LIBRARY":
		return []sbom.Purpose{sbom.Purpose_LIBRARY}
	case "CONTAINER":
		return []sbom.Purpose{sbom.Purpose_CONTAINER}
	case "OPERATING-SYSTEM":
		return []sbom.Purpose{sbom.Purpose_OPERATING_SYSTEM}
	case "DEVICE":
		return []sbom.Purpose{sbom.Purpose_DEVICE}
	case "FIRMWARE":
		return []sbom.Purpose{sbom.Purpose_FIRMWARE}
	case purposeSource:
		return []sbom.Purpose{sbom.Purpose_SOURCE}
	case "ARCHIVE":
		return []sbom.Purpose{sbom.Purpose_ARCHIVE}
	case "FILE":
		return []sbom.Purpose{sbom.Purpose_FILE}
	case "INSTALL":
		return []sbom.Purpose{sbom.Purpose_INSTALL}
	case purposeOther:
		return []sbom.Purpose{sbom.Purpose_OTHER}
	default:
		return nil
	}
}

// relationshipEdgeTypes inverts edgeTypeRelationships. Relationship
// types with no protobom edge type (such as PATCH_FOR) resolve to the
// zero value Edge_UNKNOWN, which protobom's own unserializer uses for
// unknown relationship types.
var relationshipEdgeTypes = func() map[RelationshipType]sbom.Edge_Type {
	m := make(map[RelationshipType]sbom.Edge_Type, len(edgeTypeRelationships))
	for edgeType, relType := range edgeTypeRelationships {
		m[relType] = edgeType
	}
	return m
}()
