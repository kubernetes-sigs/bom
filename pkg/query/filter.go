/*
Copyright 2022 The Kubernetes Authors.

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

package query

import "sigs.k8s.io/bom/pkg/spdx"

type Filter interface {
	Apply(map[string]spdx.Object) (map[string]spdx.Object, error)
}

type FilterResults struct {
	Objects map[string]spdx.Object
	Error   error
}

func (fr *FilterResults) Apply(filter Filter) *FilterResults {
	// If the filter results have an error. Stop here
	if fr.Error != nil {
		return fr
	}

	newObjSet, err := filter.Apply(fr.Objects)
	if err != nil {
		fr.Error = err
		return fr
	}
	fr.Objects = newObjSet
	return fr
}

type DepthFilter struct {
	TargetDepth int
}

func (f *DepthFilter) Apply(objects map[string]spdx.Object) (map[string]spdx.Object, error) {
	// Perform filter
	return searchDepth(objects, 0, uint(f.TargetDepth)), nil
}

func searchDepth(objectSet map[string]spdx.Object, currentDepth, targetDepth uint) map[string]spdx.Object {
	// If we are at target depth, we are done
	if targetDepth == currentDepth {
		return objectSet
	}

	res := map[string]spdx.Object{}
	for _, o := range objectSet {
		// If not, cycle the objects relationships to search further down
		for _, r := range *o.GetRelationships() {
			if r.Peer != nil && r.Peer.SPDXID() != "" {
				res[r.Peer.SPDXID()] = r.Peer
			}
		}
	}
	if targetDepth == currentDepth {
		return res
	}

	return searchDepth(res, currentDepth+1, targetDepth)
}

// res = elements.Apply(filter).Apply(filter).Apply(filter)
