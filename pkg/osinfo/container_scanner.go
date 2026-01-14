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
	"fmt"
	"strings"

	purl "github.com/package-url/packageurl-go"
	"github.com/sirupsen/logrus"
)

const (
	OsReleasePath    = "etc/os-release"
	AltOSReleasePath = "usr/lib/os-release"
)

type containerOSScanner interface {
	ReadOSPackages(layers []string) (layer int, pk *[]PackageDBEntry, err error)
	ParseDB(path string) (pk *[]PackageDBEntry, err error)
	OSType() OSType
	PURLType() string
}

// ReadOSPackages reads a bunch of layers and extracts the os package
// information from them, it returns the OS package and the layer where
// they are defined. If the OS is not supported, we return a nil pointer.
func ReadOSPackages(layers []string) (
	layerNum int, packages *[]PackageDBEntry, err error,
) {
	if len(layers) == 0 {
		return 0, nil, nil
	}

	ls := newLayerScanner()

	// First, let's try to determine which OS the container is based on
	osKind := OSType("")
	osInfoLayerNum := 0
	for i, lp := range layers {
		exists, err := ls.FileExistsInTar(lp, OsReleasePath, AltOSReleasePath)
		if err != nil {
			return 0, nil, fmt.Errorf("checking if file exists in layer: %w", err)
		}
		if exists {
			logrus.Debugf(" > found os-release in layer %d", i)
			osInfoLayerNum = i
		}
	}

	osKind, err = ls.OSType(layers[osInfoLayerNum])
	if err != nil {
		return 0, nil, fmt.Errorf("reading os type from layer: %w", err)
	}

	var cs containerOSScanner
	switch osKind {
	case OSDebian, OSUbuntu:
		cs = newDebianScanner()
	case OSAlpine, OSWolfi:
		cs = newAlpineScanner()
	case OSAmazonLinux, OSFedora, OSRHEL:
		cs = newRPMScanner()
	case OSDistroless:
		cs = newDistrolessScanner()
	default:
		return 0, nil, nil
	}
	layerNum, packages, err = cs.ReadOSPackages(layers)
	setPurlData(cs.PURLType(), string(osKind), packages)
	return layerNum, packages, err
}

// setPurlData stamps al found packages with the purl type and NS.
func setPurlData(ptype, pnamespace string, packages *[]PackageDBEntry) {
	if packages == nil {
		return
	}
	for i := range *packages {
		(*packages)[i].Type = ptype
		(*packages)[i].Namespace = pnamespace
	}
}

type PackageDBEntry struct {
	Package         string
	Version         string
	Architecture    string
	Type            string // purl package type (ref: https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst)
	Namespace       string // purl namespace
	MaintainerName  string
	MaintainerEmail string
	HomePage        string
	License         string // License expression
	Checksums       map[string]string
}

// PackageURL returns a purl representing the db entry. If the entry
// does not have enough data to generate the purl, it will return an
// empty string.
func (e *PackageDBEntry) PackageURL() string {
	// We require type, package, namespace and version at the very
	// least to generate a purl
	if e.Package == "" || e.Version == "" || e.Namespace == "" || e.Type == "" {
		return ""
	}

	qualifiersMap := map[string]string{}

	// Add the architecture
	// TODO(puerco): Support adding the distro
	if e.Architecture != "" {
		qualifiersMap["arch"] = e.Architecture
	}
	return purl.NewPackageURL(
		e.Type, e.Namespace, e.Package,
		e.Version, purl.QualifiersFromMap(qualifiersMap), "",
	).ToString()
}

// DownloadLocation synthesizes a download location for the
// packages based on known location for the different distros.
func (e *PackageDBEntry) DownloadLocation() string {
	if e.Package == "" || e.Version == "" || e.Architecture == "" {
		return ""
	}

	// TODO: push this logic down to each ContainerScanner
	if OSType(e.Namespace) == OSDebian {
		dirName := e.Package[0:1]
		if strings.HasPrefix(e.Package, "lib") {
			dirName = e.Package[0:4]
		}
		return fmt.Sprintf(
			"http://ftp.debian.org/debian/pool/main/%s/%s/%s_%s_%s.deb",
			dirName, e.Package, e.Package, e.Version, e.Architecture,
		)
	} else if OSType(e.Namespace) == OSWolfi {
		return fmt.Sprintf(
			"https://packages.wolfi.dev/os/%s/%s-%s.apk",
			e.Architecture, e.Package, e.Version,
		)
	}

	// TODO: For other distros we need to have the distro version
	return ""
}
