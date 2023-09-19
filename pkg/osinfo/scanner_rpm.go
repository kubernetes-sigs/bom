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
	"fmt"
	"os"
	"path/filepath"

	// Import sqlite driver for rpm database
	_ "github.com/glebarez/go-sqlite"
	rpmdbpkg "github.com/knqyf263/go-rpmdb/pkg"
	"github.com/sirupsen/logrus"
)

type rpmScanner struct {
	ls layerScanner
}

func newRPMScanner() containerOSScanner {
	return &rpmScanner{
		ls: newLayerScanner(),
	}
}

func (ct *rpmScanner) PURLType() string {
	return "rpm"
}

func (ct *rpmScanner) OSType() OSType {
	return OSRHEL
}

// ReadOSPackages reads the rpm database
func (ct *rpmScanner) ReadOSPackages(layers []string) (layer int, pk *[]PackageDBEntry, err error) {
	rpmDatabase := ""

	rpmDBFiles := []string{
		"rpmdb.sqlite", // sqlite
		"Packages.db",  // ndb
		"Packages",     // BerkleyDB
	}

	for i, lp := range layers {
		tmpDBdir, err := os.MkdirTemp("", "rmpdb")
		defer os.RemoveAll(tmpDBdir)
		if err != nil {
			return 0, pk, fmt.Errorf("creating temporary rpmdb dir: %w", err)
		}
		for _, dbname := range rpmDBFiles {
			tmpDBPath := filepath.Join(tmpDBdir, dbname)
			rpmdbpath := filepath.Join("var/lib/rpm", dbname)
			exists, err := ct.ls.FileExistsInTar(lp, rpmdbpath)
			if err != nil {
				return 0, pk, fmt.Errorf("extracting rpm database: %w", err)
			}
			if exists {
				err := ct.ls.ExtractFileFromTar(lp, rpmdbpath, tmpDBPath)
				if err != nil {
					os.Remove(tmpDBPath)
					if _, ok := err.(ErrFileNotFoundInTar); ok {
						continue
					}
					return 0, pk, fmt.Errorf("extracting rpm database: %w", err)
				}
				logrus.Debugf("Layer %d has a newer version of rpm database", i)
				rpmDatabase = tmpDBPath
				layer = i
				// Skip to the next layer. A single layer shouldn't have multiple
				// database formats in it. Even if it did, we stop for the most new
				// format present in the layer
				goto NEXT_LAYER
			}
		}
	NEXT_LAYER:
	}

	if rpmDatabase == "" {
		logrus.Info("rpm database data is empty")
		return layer, nil, nil
	}

	pk, err = ct.ParseDB(rpmDatabase)
	if err != nil {
		return layer, nil, fmt.Errorf("parsing rpm database: %w", err)
	}
	return layer, pk, err
}

func (ct *rpmScanner) ParseDB(dbPath string) (*[]PackageDBEntry, error) {
	db, err := rpmdbpkg.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening rpmdb: %w", err)
	}

	pkgs, err := db.ListPackages()
	if err != nil {
		return nil, fmt.Errorf("parsing rpm db: %w", err)
	}
	packages := []PackageDBEntry{}
	for _, p := range pkgs {
		if _, ok := virtualPackages[p.Name]; ok {
			continue
		}

		packages = append(packages, PackageDBEntry{
			Package:      p.Name,
			Version:      fmt.Sprintf("%s-%s", p.Version, p.Release),
			Architecture: p.Arch,
			Type:         "rpm",
			// Namespace is set later
			MaintainerName: p.Vendor,
			// Most RPM pacakges don't have SPDX-valid license names
			// License:        p.License,
		})
	}
	return &packages, nil
}

var virtualPackages = map[string]bool{
	"gpg-pubkey": true,
}
