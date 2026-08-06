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

// FromProtobom and ToProtobom bridge this legacy SPDX object model and
// protobom documents. They are the keystone of the modernization
// strategy: the generation and parsing engines are protobom-native
// while this model survives as a compatibility facade for existing API
// consumers, converted at the boundary.
//
// The field mapping follows the conventions of protobom's own SPDX 2.3
// serializer so that documents translated through these functions and
// documents rendered directly by protobom agree on how nodes, edges
// and metadata are expressed in SPDX terms.

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/sbom"
)

// SPDX 2.3 primary-purpose literals shared by both conversion
// directions.
const (
	purposeApplication = "APPLICATION"
	purposeSource      = "SOURCE"
	purposeOther       = "OTHER"
)

// FromProtobom converts a protobom document to bom's legacy SPDX model.
//
// Nodes become *Package or *File; edges become relationships
// carrying live Peer pointers (the legacy JSON serializer requires
// them). The protobom root elements become the document's top-level
// packages and files — the legacy model has no DESCRIBES relationship
// object, root membership expresses it. Every remaining node is
// guaranteed to render exactly once in tag-value output: the first
// edge reaching a node during a breadth-first walk from the roots gets
// FullRender set, later edges to the same node do not, and nodes not
// reachable from any root are promoted to top-level elements (the same
// promotion bom's tag-value parser applies). The walk also keeps
// relationship cycles from recursing forever at render time.
//
// Data protobom can express but the legacy model cannot is dropped:
// summaries, descriptions, source info, attribution texts, properties,
// per-node dates, identifiers on file nodes, and edges whose type
// protobom does not know.
func FromProtobom(doc *sbom.Document) (*Document, error) {
	if doc == nil {
		return nil, errors.New("document is nil")
	}
	if doc.GetMetadata() == nil {
		return nil, errors.New("document metadata is nil")
	}

	ldoc := NewDocument()
	convertMetadata(doc.GetMetadata(), ldoc)

	nodes := doc.GetNodeList().GetNodes()
	objects := make([]Object, len(nodes))
	byID := map[string]int{}
	for i, node := range nodes {
		objects[i] = nodeToObject(node)
		if node.GetId() != "" {
			byID[node.GetId()] = i
		}
	}
	outgoing := expandEdges(doc.GetNodeList().GetEdges(), byID)

	// Breadth-first walk from the roots, attaching each node's outgoing
	// relationships once and flagging the first edge that reaches a
	// node as its rendering edge.
	rendered := make([]bool, len(nodes))
	processed := make([]bool, len(nodes))
	queue := []int{}
	addRoot := func(i int) error {
		if rendered[i] {
			return nil
		}
		rendered[i] = true
		queue = append(queue, i)
		switch obj := objects[i].(type) {
		case *Package:
			if err := ldoc.AddPackage(obj); err != nil {
				return fmt.Errorf("adding package %q to document: %w", nodes[i].GetId(), err)
			}
		case *File:
			if err := ldoc.AddFile(obj); err != nil {
				return fmt.Errorf("adding file %q to document: %w", nodes[i].GetId(), err)
			}
		}
		return nil
	}

	for _, id := range doc.GetNodeList().GetRootElements() {
		if i, ok := byID[id]; ok {
			if err := addRoot(i); err != nil {
				return nil, err
			}
		}
	}

	for {
		if len(queue) == 0 {
			// Promote the first node the walk has not rendered yet
			// (unreferenced, or only reachable through a cycle).
			promoted := -1
			for i := range nodes {
				if !rendered[i] {
					promoted = i
					break
				}
			}
			if promoted == -1 {
				break
			}
			if err := addRoot(promoted); err != nil {
				return nil, err
			}
		}
		i := queue[0]
		queue = queue[1:]
		if processed[i] {
			continue
		}
		processed[i] = true
		for _, t := range outgoing[i] {
			rel := &Relationship{
				Type: t.relType,
				Peer: objects[t.to],
			}
			if !rendered[t.to] {
				rel.FullRender = true
				rendered[t.to] = true
			}
			queue = append(queue, t.to)
			objects[i].AddRelationship(rel)
		}
	}

	return ldoc, nil
}

// convertMetadata fills the legacy document's header fields from the
// protobom metadata, replacing the defaults NewDocument seeds.
func convertMetadata(md *sbom.Metadata, ldoc *Document) {
	ldoc.Name = md.GetName()
	ldoc.Namespace = namespaceFromID(md.GetId())
	if md.GetDate() != nil {
		ldoc.Created = md.GetDate().AsTime()
	}

	ldoc.Creator.Person = ""
	ldoc.Creator.Organization = ""
	ldoc.Creator.Tool = nil
	for _, author := range md.GetAuthors() {
		switch {
		case author.GetIsOrg() && ldoc.Creator.Organization == "":
			ldoc.Creator.Organization = author.ToSPDX2ClientString()
		case !author.GetIsOrg() && ldoc.Creator.Person == "":
			ldoc.Creator.Person = author.ToSPDX2ClientString()
		}
	}
	for _, tool := range md.GetTools() {
		name := tool.GetName()
		if tool.GetVersion() != "" {
			name = tool.GetName() + "-" + tool.GetVersion()
		}
		ldoc.Creator.Tool = append(ldoc.Creator.Tool, name)
	}
}

// triple is one expanded edge destination: the relationship it maps to
// and the index of the target node.
type triple struct {
	relType RelationshipType
	to      int
}

// expandEdges expands the edge list into per-source-node triples,
// dropping edges that do not connect two known nodes or whose type has
// no SPDX relationship.
func expandEdges(edges []*sbom.Edge, byID map[string]int) map[int][]triple {
	outgoing := map[int][]triple{}
	for _, edge := range edges {
		from, ok := byID[edge.GetFrom()]
		if !ok {
			continue
		}
		relType, ok := edgeTypeRelationships[edge.GetType()]
		if !ok {
			continue
		}
		for _, dest := range edge.GetTo() {
			if to, ok := byID[dest]; ok {
				outgoing[from] = append(outgoing[from], triple{relType: relType, to: to})
			}
		}
	}
	return outgoing
}

// namespaceFromID derives the SPDX document namespace from a protobom
// document ID, following protobom's serializer convention: a URI keeps
// its value with any #SPDXRef-DOCUMENT fragment stripped, anything
// else maps to a deterministic urn:uuid, and an empty ID stays empty
// for the caller to fill in.
func namespaceFromID(id string) string {
	if id == "" {
		return ""
	}
	u, err := url.Parse(id)
	if err != nil || u.Scheme == "" || (u.Fragment != "" && u.Fragment != "SPDXRef-DOCUMENT") {
		return "urn:uuid:" + uuid.NewSHA1(uuid.MustParse(sbom.NamespaceUUID), []byte(id)).String()
	}
	return strings.Replace(id, "#SPDXRef-DOCUMENT", "", 1)
}

// spdxID returns the node identifier in the SPDXRef- form the legacy
// model renders verbatim. protobom node identifiers read from SPDX
// documents have the prefix stripped.
func spdxID(id string) string {
	if id == "" || strings.HasPrefix(id, "SPDXRef-") {
		return id
	}
	return "SPDXRef-" + id
}

func nodeToObject(node *sbom.Node) Object {
	if node.GetType() == sbom.Node_FILE {
		return nodeToFile(node)
	}
	return nodeToPackage(node)
}

func nodeToPackage(node *sbom.Node) *Package {
	p := NewPackage()
	p.SetSPDXID(spdxID(node.GetId()))
	p.Name = node.GetName()
	p.Version = node.GetVersion()
	p.FileName = node.GetFileName()
	p.DownloadLocation = node.GetUrlDownload()
	p.HomePage = node.GetUrlHome()
	p.LicenseConcluded = node.GetLicenseConcluded()
	p.LicenseDeclared = strings.Join(node.GetLicenses(), " OR ")
	p.LicenseComments = node.GetLicenseComments()
	p.CopyrightText = strings.TrimSpace(node.GetCopyright())
	p.Comment = node.GetComment()
	p.Checksum = checksums(node.GetHashes())
	p.ExternalRefs = externalRefs(node)
	p.PrimaryPurpose = primaryPurpose(node)

	if suppliers := node.GetSuppliers(); len(suppliers) > 0 {
		if s := suppliers[0]; s.GetIsOrg() {
			p.Supplier.Organization = s.ToSPDX2ClientString()
		} else {
			p.Supplier.Person = s.ToSPDX2ClientString()
		}
	}
	if originators := node.GetOriginators(); len(originators) > 0 {
		if o := originators[0]; o.GetIsOrg() {
			p.Originator.Organization = o.ToSPDX2ClientString()
		} else {
			p.Originator.Person = o.ToSPDX2ClientString()
		}
	}
	return p
}

func nodeToFile(node *sbom.Node) *File {
	f := NewFile()
	f.SetSPDXID(spdxID(node.GetId()))
	f.Name = node.GetName()
	f.FileType = node.GetFileTypes()
	f.LicenseConcluded = node.GetLicenseConcluded()
	// The legacy model stores the license info found in the file as a
	// single expression; bom's JSON parser joins multiple entries the
	// same way.
	f.LicenseInfoInFile = strings.Join(node.GetLicenses(), " AND ")
	f.LicenseComments = node.GetLicenseComments()
	f.CopyrightText = strings.TrimSpace(node.GetCopyright())
	f.Checksum = checksums(node.GetHashes())
	return f
}

// checksums converts a protobom hash map to the legacy algorithm-name
// keyed map, dropping algorithms SPDX 2.x has no name for.
func checksums(hashes map[int32]string) map[string]string {
	if len(hashes) == 0 {
		return nil
	}
	out := map[string]string{}
	for algo, value := range hashes {
		if _, ok := sbom.HashAlgorithm_name[algo]; !ok {
			continue
		}
		if name := sbom.HashAlgorithm(algo).ToSPDX(); name != "" {
			out[string(name)] = value
		}
	}
	return out
}

// externalRefs renders the node's external references and software
// identifiers as legacy external references, identifiers last and
// sorted by type for deterministic output.
func externalRefs(node *sbom.Node) []ExternalRef {
	refs := []ExternalRef{}
	for _, er := range node.GetExternalReferences() {
		if er.GetUrl() == "" {
			continue
		}
		refs = append(refs, ExternalRef{
			Category: extRefCategory(er.GetType()),
			Type:     extRefType(er.GetType()),
			Locator:  er.GetUrl(),
		})
	}

	identifiers := make([]int32, 0, len(node.GetIdentifiers()))
	for t := range node.GetIdentifiers() {
		identifiers = append(identifiers, t)
	}
	slices.Sort(identifiers)
	for _, t := range identifiers {
		idType := sbom.SoftwareIdentifierType(t)
		refs = append(refs, ExternalRef{
			Category: idType.ToSPDX2Category(),
			Type:     idType.ToSPDX2Type(),
			Locator:  node.GetIdentifiers()[t],
		})
	}
	if len(refs) == 0 {
		return nil
	}
	return refs
}

// extRefCategory mirrors protobom's external reference category
// mapping (extRefCategoryFromProtobomExtRef, unexported there).
func extRefCategory(t sbom.ExternalReference_ExternalReferenceType) string {
	switch t {
	case sbom.ExternalReference_BOWER,
		sbom.ExternalReference_MAVEN_CENTRAL,
		sbom.ExternalReference_NPM,
		sbom.ExternalReference_NUGET:
		return CatPackageManager
	case sbom.ExternalReference_SECURITY_ADVISORY,
		sbom.ExternalReference_SECURITY_FIX,
		sbom.ExternalReference_SECURITY_OTHER:
		return "SECURITY"
	default:
		return purposeOther
	}
}

// extRefType mirrors protobom's external reference type mapping
// (extRefTypeFromProtobomExtRef, unexported there).
func extRefType(t sbom.ExternalReference_ExternalReferenceType) string {
	switch t {
	case sbom.ExternalReference_BOWER:
		return "bower"
	case sbom.ExternalReference_MAVEN_CENTRAL:
		return "maven-central"
	case sbom.ExternalReference_NPM:
		return "npm"
	case sbom.ExternalReference_NUGET:
		return "nuget"
	case sbom.ExternalReference_SECURITY_ADVISORY:
		return "advisory"
	case sbom.ExternalReference_SECURITY_FIX:
		return "fix"
	case sbom.ExternalReference_SECURITY_OTHER:
		return "url"
	default:
		return purposeOther
	}
}

// primaryPurpose maps the node's first primary purpose to the SPDX 2.3
// package purpose vocabulary, the same collapsing protobom's
// serializer applies. The legacy model holds a single purpose.
func primaryPurpose(node *sbom.Node) string {
	purposes := node.GetPrimaryPurpose()
	if len(purposes) == 0 {
		return ""
	}
	switch purposes[0] {
	case sbom.Purpose_UNKNOWN_PURPOSE:
		return ""
	case sbom.Purpose_APPLICATION, sbom.Purpose_EXECUTABLE:
		return purposeApplication
	case sbom.Purpose_FRAMEWORK:
		return "FRAMEWORK"
	case sbom.Purpose_LIBRARY, sbom.Purpose_MODULE:
		return "LIBRARY"
	case sbom.Purpose_CONTAINER:
		return "CONTAINER"
	case sbom.Purpose_OPERATING_SYSTEM:
		return "OPERATING-SYSTEM"
	case sbom.Purpose_DEVICE, sbom.Purpose_DEVICE_DRIVER:
		return "DEVICE"
	case sbom.Purpose_FIRMWARE:
		return "FIRMWARE"
	case sbom.Purpose_SOURCE, sbom.Purpose_PATCH:
		return purposeSource
	case sbom.Purpose_ARCHIVE:
		return "ARCHIVE"
	case sbom.Purpose_FILE:
		return "FILE"
	case sbom.Purpose_INSTALL:
		return "INSTALL"
	default:
		return purposeOther
	}
}

// edgeTypeRelationships maps protobom edge types to legacy SPDX
// relationship types, matching protobom's serializer table
// (edgeTypeToSPDXRel, unexported there). Edge_UNKNOWN is absent on
// purpose: the legacy renderer rejects empty relationship types.
var edgeTypeRelationships = map[sbom.Edge_Type]RelationshipType{
	sbom.Edge_amends:               AMENDS,
	sbom.Edge_ancestor:             ANCESTOR_OF,
	sbom.Edge_buildDependency:      BUILD_DEPENDENCY_OF,
	sbom.Edge_buildTool:            BUILD_TOOL_OF,
	sbom.Edge_contains:             CONTAINS,
	sbom.Edge_contained_by:         CONTAINED_BY,
	sbom.Edge_copy:                 COPY_OF,
	sbom.Edge_dataFile:             DATA_FILE_OF,
	sbom.Edge_dependencyManifest:   DEPENDENCY_MANIFEST_OF,
	sbom.Edge_dependsOn:            DEPENDS_ON,
	sbom.Edge_dependencyOf:         DEPENDENCY_OF,
	sbom.Edge_descendant:           DESCENDANT_OF,
	sbom.Edge_describes:            DESCRIBES,
	sbom.Edge_describedBy:          DESCRIBED_BY,
	sbom.Edge_devDependency:        DEV_DEPENDENCY_OF,
	sbom.Edge_devTool:              DEV_TOOL_OF,
	sbom.Edge_distributionArtifact: DISTRIBUTION_ARTIFACT,
	sbom.Edge_documentation:        DOCUMENTATION_OF,
	sbom.Edge_dynamicLink:          DYNAMIC_LINK,
	sbom.Edge_example:              EXAMPLE_OF,
	sbom.Edge_expandedFromArchive:  EXPANDED_FROM_ARCHIVE,
	sbom.Edge_fileAdded:            FILE_ADDED,
	sbom.Edge_fileDeleted:          FILE_DELETED,
	sbom.Edge_fileModified:         FILE_MODIFIED,
	sbom.Edge_generates:            GENERATES,
	sbom.Edge_generatedFrom:        GENERATED_FROM,
	sbom.Edge_metafile:             METAFILE_OF,
	sbom.Edge_optionalComponent:    OPTIONAL_COMPONENT_OF,
	sbom.Edge_optionalDependency:   OPTIONAL_DEPENDENCY_OF,
	sbom.Edge_other:                OTHER,
	sbom.Edge_packages:             PACKAGE_OF,
	sbom.Edge_patch:                PATCH_APPLIED,
	sbom.Edge_prerequisite:         HAS_PREREQUISITE,
	sbom.Edge_prerequisiteFor:      PREREQUISITE_FOR,
	sbom.Edge_providedDependency:   PROVIDED_DEPENDENCY_OF,
	sbom.Edge_requirementFor:       REQUIREMENT_DESCRIPTION_FOR,
	sbom.Edge_runtimeDependency:    RUNTIME_DEPENDENCY_OF,
	sbom.Edge_specificationFor:     SPECIFICATION_FOR,
	sbom.Edge_staticLink:           STATIC_LINK,
	sbom.Edge_test:                 TEST_OF,
	sbom.Edge_testCase:             TEST_CASE_OF,
	sbom.Edge_testDependency:       TEST_DEPENDENCY_OF,
	sbom.Edge_testTool:             TEST_TOOL_OF,
	sbom.Edge_variant:              VARIANT_OF,
}
