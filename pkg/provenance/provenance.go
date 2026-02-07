/*
Copyright 2021 The Kubernetes Authors.

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

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

package provenance

import (
	"fmt"
	"os"

	slsa02 "github.com/in-toto/attestation/go/predicates/provenance/v02"
	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

// LoadStatement loads a statement from a json file.
func LoadStatement(path string) (s *Statement, err error) {
	statement := NewSLSAStatement()

	jsonData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening stament JSON file: %w", err)
	}
	err = protojson.UnmarshalOptions{}.Unmarshal(jsonData, statement)
	if err != nil {
		return nil, fmt.Errorf("decoding attestation JSON data: %w", err)
	}

	// The protojson unmarshal populates the embedded intoto.Statement proto
	// fields, including the predicate as a *structpb.Struct. Re-parse that
	// into the typed predicate wrapper.
	if statement.GetPredicate() != nil {
		predData, err := protojson.Marshal(statement.GetPredicate())
		if err != nil {
			return nil, fmt.Errorf("re-marshaling predicate struct: %w", err)
		}

		switch statement.PredicateType {
		case "https://slsa.dev/provenance/v0.1", "https://slsa.dev/provenance/v0.2":
			pred := &slsa02.Provenance{}
			err := (protojson.UnmarshalOptions{
				DiscardUnknown: true,
			}).Unmarshal(predData, pred)
			if err != nil {
				return nil, fmt.Errorf("unmarshaling predicate: %w", err)
			}
			statement.Predicate = &Predicate{PredicateContent: pred}
		default:
			return nil, fmt.Errorf("unsupported predicate type: %s", statement.PredicateType)
		}
	}

	return statement, nil
}

// NewSLSAStatement creates a new attestation.
func NewSLSAStatement() *Statement {
	return &Statement{
		impl: &defaultStatementImplementation{},
		Statement: intoto.Statement{
			Type:          intoto.StatementTypeUri,
			Subject:       []*intoto.ResourceDescriptor{},
			PredicateType: "https://slsa.dev/provenance/v0.2",
		},
		Predicate: NewSLSAPredicate(),
	}
}

// NewSLSAPredicate returns a new SLSA provenance predicate.
func NewSLSAPredicate() *Predicate {
	return &Predicate{
		PredicateContent: &slsa02.Provenance{
			Builder:     &slsa02.Builder{},
			BuildType:   "",
			Invocation:  &slsa02.Invocation{},
			BuildConfig: &structpb.Struct{},
			Metadata:    &slsa02.Metadata{},
			Materials:   []*slsa02.Material{},
		},
	}
}

// Envelope is the outermost layer of the attestation, handling authentication and
// serialization. The format and protocol are defined in DSSE and adopted by in-toto in ITE-5.
// https://github.com/in-toto/attestation/blob/main/spec/README.md#envelope
type Envelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signatures  []any  `json:"signatures"`
}
