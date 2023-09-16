/*
Copyright 2023 The Kubernetes Authors.

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

package osinfo

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const distrolessDebianPkgDir = "var/lib/dpkg/status.d/"

type distrolessScanner struct {
	baseDistro OSType
	ls         layerScanner
}

func newDistrolessScanner() containerOSScanner {
	return &distrolessScanner{ls: newLayerScanner()}
}

func (ct *distrolessScanner) PURLType() string {
	return "deb"
}

func (ct *distrolessScanner) OSType() OSType {
	return OSDistroless
}

// ReadOSPackages reads the installed package configuration in the distroless
// image. The debian database will be extracted to a temporary directory
func (ct *distrolessScanner) ReadOSPackages(layers []string) (layer int, pk *[]PackageDBEntry, err error) {
	tmpDBPath, err := os.MkdirTemp("", "distroless-db-")
	if err != nil {
		return 0, pk, fmt.Errorf("opening temporary apkdb file: %w", err)
	}
	defer os.RemoveAll(tmpDBPath)

	for i, lp := range layers {
		if err := ct.ls.ExtractDirectoryFromTar(lp, distrolessDebianPkgDir, tmpDBPath); err != nil && !errors.Is(err, ErrFileNotFoundInTar{}) {
			return 0, nil, fmt.Errorf("extracting distroless pkg db: %w", err)
		}
		layer = i
	}

	// Call the database parser
	db, err := ct.ParseDB(filepath.Join(tmpDBPath, distrolessDebianPkgDir))
	if err != nil {
		return 0, nil, fmt.Errorf("parsing distroless database: %w", err)
	}
	return layer, db, nil
}

// ParseDB parses the split dpkg database extracted from the distroless filesystem
func (ct *distrolessScanner) ParseDB(path string) (*[]PackageDBEntry, error) {
	dpkgScanner := debianScanner{}
	db := []PackageDBEntry{}

	files, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("reading temporary database files: %w", err)
	}

	for _, f := range files {
		// TODO(puerco): Process file data too. We're skipping it atm
		if strings.HasSuffix(f.Name(), ".md5sums") {
			continue
		}
		singlePackage, err := dpkgScanner.ParseDB(filepath.Join(path, f.Name()))
		if err != nil {
			return nil, fmt.Errorf("parsing database file %s: %w", f.Name(), err)
		}
		db = append(db, *singlePackage...)
	}

	return &db, nil
}
