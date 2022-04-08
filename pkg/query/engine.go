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

import (
	"github.com/pkg/errors"
	"sigs.k8s.io/bom/pkg/spdx"
)

type Engine struct {
	Document *spdx.Document
	MaxDepth int
}

// Open reads a document from the specified path
func (e *Engine) Open(path string) error {
	doc, err := spdx.OpenDoc(path)
	if err != nil {
		return errors.Wrap(err, "opening doc")
	}
	e.Document = doc
	return nil
}

// Query takes an expression as a string and filters de document
func (e *Engine) Query(expressionText string) error {
	if e.Document == nil {
		return errors.New("query engine has no document open")
	}
	_, err := NewExpression(expressionText)
	if err != nil {
		return errors.Wrap(err, "parsing expression")
	}
	return nil
}
