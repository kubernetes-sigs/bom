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
	"bufio"
	"fmt"
	"os"
	"strings"

	purl "github.com/package-url/packageurl-go"
	"github.com/sirupsen/logrus"
)

type debianScanner struct {
	ls layerScanner
}

func newDebianScanner() containerOSScanner {
	return &debianScanner{ls: newLayerScanner()}
}

func (ct *debianScanner) PURLType() string {
	return "deb"
}

func (ct *debianScanner) OSType() OSType {
	return OSDebian
}

// ReadDebianPackages scans through a set of container layers looking for the
// last update to the debian package database. If found, extracts it and
// sends it to parseDpkgDB to extract the package information from the file.
func (ct *debianScanner) ReadOSPackages(layers []string) (layer int, pk *[]PackageDBEntry, err error) {
	// Cycle the layers in order, trying to extract the dpkg database
	dpkgDatabase := ""

	for i, lp := range layers {
		dpkgDB, err := os.CreateTemp("", "dpkg-")
		if err != nil {
			return 0, pk, fmt.Errorf("opening temp dpkg file: %w", err)
		}
		dpkgPath := dpkgDB.Name()
		if err := ct.ls.ExtractFileFromTar(lp, "var/lib/dpkg/status", dpkgPath); err != nil {
			os.Remove(dpkgDB.Name())
			if _, ok := err.(ErrFileNotFoundInTar); ok {
				continue
			}
			return 0, pk, fmt.Errorf("extracting dpkg database: %w", err)
		}
		logrus.Infof("Layer %d has a newer version of dpkg database", i)
		dpkgDatabase = dpkgPath
		layer = i
	}

	if dpkgDatabase == "" {
		logrus.Info("dbdata is blank")
		return layer, nil, nil
	}
	defer os.Remove(dpkgDatabase)
	pk, err = ct.ParseDB(dpkgDatabase)
	return layer, pk, err
}

// parseDpkgDB reads a dpks database and populates a slice of PackageDBEntry
// with information from the packages found.
func (ct *debianScanner) ParseDB(dbPath string) (*[]PackageDBEntry, error) {
	file, err := os.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening for reading: %w", err)
	}
	defer file.Close()
	logrus.Debugf("Scanning data from dpkg database in %s", dbPath)
	db := []PackageDBEntry{}
	scanner := bufio.NewScanner(file)
	var curPkg *PackageDBEntry
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ":", 2)
		if len(parts) < 2 {
			continue
		}

		switch parts[0] {
		case "Package":
			if curPkg != nil {
				db = append(db, *curPkg)
			}
			curPkg = &PackageDBEntry{
				Package: strings.TrimSpace(parts[1]),
				Type:    purl.TypeDebian,
			}
		case "Architecture":
			if curPkg != nil {
				curPkg.Architecture = strings.TrimSpace(parts[1])
			}
		case "Version":
			if curPkg != nil {
				curPkg.Version = strings.TrimSpace(parts[1])
			}
		case "Homepage":
			if curPkg != nil {
				curPkg.HomePage = strings.TrimSpace(parts[1])
			}
		case "Maintainer":
			if curPkg != nil {
				mparts := strings.SplitN(parts[1], "<", 2)
				if len(mparts) == 2 {
					curPkg.MaintainerName = strings.TrimSpace(mparts[0])
					curPkg.MaintainerEmail = strings.TrimSuffix(strings.TrimSpace(mparts[1]), ">")
				}
			}
		}
	}

	// Add the last package
	if curPkg != nil {
		db = append(db, *curPkg)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning database file: %w", err)
	}

	return &db, err
}
