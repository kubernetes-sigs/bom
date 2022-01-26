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

package osinfo

import (
	"bufio"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// TODO: Move functions to its own implementation
type ContainerScanner struct{}

// ReadOSPackages reads a bunch of layers and extracts the os package
// information from them, it returns the OS package and the layer where
// they are defined. If the OS is not supported, we return a nil pointer.
func (ct *ContainerScanner) ReadOSPackages(layers []string) (
	layerNum int, packages *[]PackageDBEntry, err error,
) {
	loss := LayerScanner{}

	// First, let's try to determine which OS the container is based on
	osKind := ""
	for _, lp := range layers {
		osKind, err = loss.OSType(lp)
		if err != nil {
			return 0, nil, errors.Wrap(err, "reading os type from layer")
		}
		if osKind != "" {
			break
		}
	}

	if osKind == OSDebian {
		return ct.ReadDebianPackages(layers)
	}
	return 0, nil, nil
}

// ReadDebianPackages scans through a set of container layers looking for the
// last update to the debian package datgabase. If found, extracts it and
// sends it to parseDpkgDB to extract the package information from the file.
func (ct *ContainerScanner) ReadDebianPackages(layers []string) (layer int, pk *[]PackageDBEntry, err error) {
	// Cycle the layers in order, trying to extract the dpkg database
	dpkgDatabase := ""
	loss := LayerScanner{}
	for i, lp := range layers {
		dpkgDB, err := os.CreateTemp("", "dpkg-")
		if err != nil {
			return 0, pk, errors.Wrap(err, "opening temp dpkg file")
		}
		dpkgPath := dpkgDB.Name()
		defer os.Remove(dpkgDB.Name())
		if err := loss.extractFileFromTar(lp, "var/lib/dpkg/status", dpkgPath); err != nil {
			if _, ok := err.(ErrFileNotFoundInTar); ok {
				continue
			}
			return 0, pk, errors.Wrap(err, "extracting dpkg database")
		}
		logrus.Infof("Layer %d has a newer version of dpkg database", i)
		dpkgDatabase = dpkgPath
		layer = i
	}

	if dpkgDatabase == "" {
		logrus.Info("dbdata is blank")
		return layer, nil, nil
	}

	pk, err = ct.parseDpkgDB(dpkgDatabase)
	return layer, pk, err
}

type PackageDBEntry struct {
	Package      string
	Version      string
	Architecture string
}

func (ct *ContainerScanner) parseDpkgDB(dbPath string) (*[]PackageDBEntry, error) {
	file, err := os.Open(dbPath)
	if err != nil {
		return nil, errors.Wrap(err, "opening for reading")
	}
	defer file.Close()
	logrus.Infof("Scanning data from dpkg database in %s", dbPath)
	db := []PackageDBEntry{}
	scanner := bufio.NewScanner(file)
	var curPkg *PackageDBEntry
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "Package:") {
			if curPkg != nil {
				db = append(db, *curPkg)
			}
			curPkg = &PackageDBEntry{
				Package: strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "Package:")),
			}
		}

		if strings.HasPrefix(scanner.Text(), "Architecture:") {
			if curPkg != nil {
				curPkg.Architecture = strings.TrimSpace(
					strings.TrimPrefix(scanner.Text(), "Architecture:"),
				)
			}
		}

		if strings.HasPrefix(scanner.Text(), "Version:") {
			if curPkg != nil {
				curPkg.Version = strings.TrimSpace(
					strings.TrimPrefix(scanner.Text(), "Version:"),
				)
			}
		}
	}

	logrus.Infof("Found %d packages", len(db))

	if err := scanner.Err(); err != nil {
		return nil, errors.Wrap(err, "scanning database file")
	}

	return &db, err
}
