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

package provenance

import (
	"fmt"
	"os"

	slsa02 "github.com/in-toto/attestation/go/predicates/provenance/v02"
	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type PredicateContent proto.Message

type Builder interface {
	GetId() string
}

type Predicate struct {
	PredicateContent
}

// AddMaterial adds an entry to the listo of materials.
func (p *Predicate) AddMaterial(rs *intoto.ResourceDescriptor) {
	switch v := p.PredicateContent.(type) {
	case *slsa02.Provenance:
		mat := &slsa02.Material{
			Uri:    rs.GetUri(),
			Digest: rs.GetDigest(),
		}
		v.Materials = append(v.Materials, mat)
	default:
		return
	}
}

func (p *Predicate) GetMaterials() []*intoto.ResourceDescriptor {
	ret := []*intoto.ResourceDescriptor{}
	//nolint:gocritic // We'll add more formats
	switch v := p.PredicateContent.(type) {
	case *slsa02.Provenance:
		for _, m := range v.GetMaterials() {
			ret = append(ret, &intoto.ResourceDescriptor{
				Uri:    m.GetUri(),
				Digest: m.GetDigest(),
			})
		}
	}
	return ret
}

func (p *Predicate) SetBuilderID(id string) {
	//nolint:gocritic // We'll add more formats
	switch v := p.PredicateContent.(type) {
	case *slsa02.Provenance:
		if v.GetBuilder() == nil {
			v.Builder = &slsa02.Builder{}
		}
		v.Builder.Id = id
	}
}

func (p *Predicate) GetBuilder() Builder {
	switch v := p.PredicateContent.(type) {
	case *slsa02.Provenance:
		return v.GetBuilder()
	default:
		return nil
	}
}

// Write outputs the predicate as JSON to a file.
func (p *Predicate) Write(path string) error {
	jsonData, err := protojson.MarshalOptions{}.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshaling predicate to json: %w", err)
	}

	if err := os.WriteFile(path, jsonData, os.FileMode(0o644)); err != nil {
		return fmt.Errorf("writing predicate file: %w", err)
	}

	return nil
}
