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
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	apk "gitlab.alpinelinux.org/alpine/go/repository"
)

const apkDBPath = "lib/apk/db/installed"

type alpineScanner struct {
	ls layerScanner
}

func newAlpineScanner() containerOSScanner {
	return &alpineScanner{ls: newLayerScanner()}
}

func (ct *alpineScanner) PURLType() string {
	return "apk"
}

func (ct *alpineScanner) OSType() OSType {
	return OSAlpine
}

// ReadApkPackages reads the last known changed copy of the apk database.
func (ct *alpineScanner) ReadOSPackages(layers []string) (layer int, pk *[]PackageDBEntry, err error) {
	apkDatabase := ""

	for i, lp := range layers {
		tmpDB, err := os.CreateTemp("", "apkdb-")
		if err != nil {
			return 0, pk, fmt.Errorf("opening temporary apkdb file: %w", err)
		}
		tmpDBPath := tmpDB.Name()
		if err := ct.ls.ExtractFileFromTar(lp, apkDBPath, tmpDBPath); err != nil {
			os.Remove(tmpDBPath)
			if _, ok := err.(ErrFileNotFoundInTar); ok {
				continue
			}
			return 0, pk, fmt.Errorf("extracting apk database: %w", err)
		}
		logrus.Debugf("Layer %d has a newer version of apk database", i)
		apkDatabase = tmpDBPath
		layer = i
	}

	if apkDatabase == "" {
		logrus.Info("apk database data is empty")
		return layer, nil, nil
	}
	defer os.Remove(apkDatabase)

	pk, err = ct.ParseDB(apkDatabase)
	if err != nil {
		return layer, nil, fmt.Errorf("parsing apk database: %w", err)
	}
	return layer, pk, err
}

func (ct *alpineScanner) ParseDB(dbPath string) (*[]PackageDBEntry, error) {
	f, err := os.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening apkdb: %w", err)
	}
	apks, err := apk.ParsePackageIndex(f)
	if err != nil {
		return nil, fmt.Errorf("parsing apk db: %w", err)
	}

	packages := []PackageDBEntry{}
	for _, p := range apks {
		cs := map[string]string{}
		if strings.HasPrefix(p.ChecksumString(), "Q1") {
			cs["SHA1"] = hex.EncodeToString(p.Checksum)
		} else if p.ChecksumString() != "" {
			cs["MD5"] = hex.EncodeToString(p.Checksum)
		}

		packages = append(packages, PackageDBEntry{
			Package:        p.Name,
			Version:        p.Version,
			Architecture:   p.Arch,
			Type:           "apk",
			MaintainerName: p.Maintainer,
			License:        p.License,
			Checksums:      cs,
		})
	}
	return &packages, nil
}
