//go:build mage
// +build mage

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

package main

import (
	"archive/zip"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/magefile/mage/sh"
	"github.com/sirupsen/logrus"
	"github.com/uwu-tools/magex/pkg"

	"sigs.k8s.io/bom/pkg/license"
	"sigs.k8s.io/release-utils/mage"
	"sigs.k8s.io/release-utils/util"
)

// Default target to run when none is specified
// If not set, running mage will list available targets
var Default = Verify

const (
	binDir    = "bin"
	scriptDir = "scripts"
	oldLicErr = "latest SPDX license version not embedded"
)

var boilerplateDir = filepath.Join(scriptDir, "boilerplate")

// All runs all targets for this repository
func All() error {
	if err := Verify(); err != nil {
		return err
	}

	if err := Test(); err != nil {
		return err
	}

	return nil
}

// Test runs various test functions
func Test() error {
	if err := mage.TestGo(true); err != nil {
		return err
	}

	return nil
}

// Verify runs repository verification scripts
func Verify() error {
	fmt.Println("Ensuring mage is available...")
	if err := pkg.EnsureMage(""); err != nil {
		return err
	}

	fmt.Println("Running copyright header checks...")
	if err := mage.VerifyBoilerplate("v0.2.5", binDir, boilerplateDir, false); err != nil {
		return err
	}

	fmt.Println("Running external dependency checks...")
	if err := mage.VerifyDeps("v0.3.0", "", "", true); err != nil {
		return err
	}

	fmt.Println("Running go module linter...")
	if err := mage.VerifyGoMod(scriptDir); err != nil {
		return err
	}

	fmt.Println("Running golangci-lint...")
	if err := mage.RunGolangCILint("", false); err != nil {
		return err
	}

	if err := Build(); err != nil {
		return err
	}

	return nil
}

// Build runs go build
func Build() error {
	fmt.Println("Running go build...")

	ldFlag, err := mage.GenerateLDFlags()
	if err != nil {
		return err
	}

	os.Setenv("BOM_LDFLAGS", ldFlag)

	if err := mage.VerifyBuild(scriptDir); err != nil {
		return err
	}

	fmt.Println("Binaries available in the output directory.")
	return nil
}

func BuildBinariesSnapshot() error {
	fmt.Println("Building binaries with goreleaser in snapshot mode...")

	ldFlag, err := mage.GenerateLDFlags()
	if err != nil {
		return err
	}

	os.Setenv("BOM_LDFLAGS", ldFlag)

	return sh.RunV("goreleaser", "release", "--clean",
		"--snapshot", "--skip-sign")
}

func BuildBinaries() error {
	fmt.Println("Building binaries with goreleaser...")

	ldFlag, err := mage.GenerateLDFlags()
	if err != nil {
		return err
	}

	os.Setenv("BOM_LDFLAGS", ldFlag)

	return sh.RunV("goreleaser", "release", "--clean")
}

// BuildImages build bom image using ko
func BuildImages() error {
	fmt.Println("Building images with ko...")

	gitVersion := getVersion()
	gitCommit := getCommit()
	ldFlag, err := mage.GenerateLDFlags()
	if err != nil {
		return err
	}
	os.Setenv("BOM_LDFLAGS", ldFlag)
	os.Setenv("KOCACHE", "/tmp/ko")

	if os.Getenv("KO_DOCKER_REPO") == "" {
		return errors.New("missing KO_DOCKER_REPO environment variable")
	}

	return sh.RunV("ko", "build", "--bare",
		"--platform=all", "--tags", gitVersion, "--tags", gitCommit,
		"sigs.k8s.io/bom/cmd/bom")
}

// BuildImagesLocal build images locally and not push
func BuildImagesLocal() error {
	fmt.Println("Building image with ko for local test...")
	if err := mage.EnsureKO(""); err != nil {
		return err
	}

	ldFlag, err := mage.GenerateLDFlags()
	if err != nil {
		return err
	}

	os.Setenv("BOM_LDFLAGS", ldFlag)
	os.Setenv("KOCACHE", "/tmp/ko")

	return sh.RunV("ko", "build", "--bare",
		"--local", "--platform=linux/amd64",
		"sigs.k8s.io/bom/cmd/bom")
}

func BuildStaging() error {
	fmt.Println("Ensuring mage is available...")
	if err := pkg.EnsureMage(""); err != nil {
		return err
	}

	if err := mage.EnsureKO(""); err != nil {
		return err
	}

	if err := BuildImages(); err != nil {
		return fmt.Errorf("building the images: %w", err)
	}

	return nil
}

func Clean() {
	fmt.Println("Cleaning workspace...")
	toClean := []string{"output"}

	for _, clean := range toClean {
		sh.Rm(clean)
	}

	fmt.Println("Done.")
}

// getVersion gets a description of the commit, e.g. v0.30.1 (latest) or v0.30.1-32-gfe72ff73 (canary)
func getVersion() string {
	version, _ := sh.Output("git", "describe", "--tags", "--match=v*")
	if version != "" {
		return version
	}

	// repo without any tags in it
	return "v0.0.0"
}

// getCommit gets the hash of the current commit
func getCommit() string {
	commit, _ := sh.Output("git", "rev-parse", "--short", "HEAD")
	return commit
}

// getGitState gets the state of the git repository
func getGitState() string {
	_, err := sh.Output("git", "diff", "--quiet")
	if err != nil {
		return "dirty"
	}

	return "clean"
}

// getBuildDateTime gets the build date and time
func getBuildDateTime() string {
	result, _ := sh.Output("git", "log", "-1", "--pretty=%ct")
	if result != "" {
		sourceDateEpoch := fmt.Sprintf("@%s", result)
		date, _ := sh.Output("date", "-u", "-d", sourceDateEpoch, "+%Y-%m-%dT%H:%M:%SZ")
		return date
	}

	date, _ := sh.Output("date", "+%Y-%m-%dT%H:%M:%SZ")
	return date
}

// CheckEmbeddedData is a magefile-exposed function that checks that the
// licensedata is the latest version available. If not returns oldLicErr
func CheckEmbeddedData() error {
	if err := checkEmbeddedDataWithTag(""); err != nil {
		if !strings.HasPrefix(err.Error(), oldLicErr) {
			logrus.Error("")
			logrus.Error("Your local fork does not have the embedded data for the latest")
			logrus.Error("version of the SPDX license list. To fix this, please run")
			logrus.Error("the following command from a clean fork:")
			logrus.Error("")
			logrus.Error("  mage UpdateEmbeddedData")
			logrus.Error("")
			logrus.Error("and commit the results under pkg/license/data")
		}
		return err
	}
	logrus.Info("Embedded license data seems to be up to date 👍")
	return nil
}

// checkEmbeddedDataWithTag gets a tag and ensures that the current version
// of the SPDX license data is that version. If the tag is an empty string it
// will check GitHub foir the latest version available
func checkEmbeddedDataWithTag(tag string) (err error) {
	catalog, err := license.NewCatalogWithOptions(license.DefaultCatalogOpts)
	if err != nil {
		return fmt.Errorf("generating license catalog")
	}

	// Get the latest SPDX license version
	if tag == "" {
		tag, err = catalog.Downloader.GetLatestTag()
		if err != nil {
			return fmt.Errorf("fetching last license list version: %w", err)
		}
	}

	if !util.Exists(
		filepath.Join(license.EmbeddedDataDir, fmt.Sprintf("license-list-%s.zip", tag)),
	) {
		return fmt.Errorf("%s (%s)", oldLicErr, tag)
	}
	return nil
}

// UpdateEmbeddedData updates the data in the license package to the
// latest version if the SPDX license list
func UpdateEmbeddedData() error {
	catalog, err := license.NewCatalogWithOptions(license.DefaultCatalogOpts)
	if err != nil {
		return fmt.Errorf("generating license catalog")
	}

	tag, err := catalog.Downloader.GetLatestTag()
	if err != nil {
		return fmt.Errorf("fetching last license list version: %w", err)
	}

	if checkError := checkEmbeddedDataWithTag(tag); checkError != nil {
		if !strings.HasPrefix(checkError.Error(), oldLicErr) {
			return fmt.Errorf("checking latest spdx version: %w", checkError)
		}
	}

	if util.Exists(license.EmbeddedDataDir) {
		if err := os.RemoveAll(license.EmbeddedDataDir); err != nil {
			return fmt.Errorf("removing embedded data: %w", err)
		}
	}

	if err := os.MkdirAll(
		filepath.Join(license.EmbeddedDataDir), os.FileMode(0o755),
	); err != nil {
		return fmt.Errorf("creating cached license path: %w", err)
	}

	tmpPath, err := os.CreateTemp("", "license-download-")
	if err != nil {
		return fmt.Errorf("creating tmp file: %w", err)
	}
	defer os.Remove(tmpPath.Name())

	if err := catalog.Downloader.DownloadLicenseListToFile(tag, tmpPath.Name()); err != nil {
		return fmt.Errorf("downloading licenses: %w", err)
	}
	// Extract the license data, to just embed the bits we care about
	if _, err := tmpPath.Seek(0, 0); err != nil {
		return fmt.Errorf("rewqinding file: %w", err)
	}

	i, err := os.Stat(tmpPath.Name())
	if err != nil {
		return fmt.Errorf("getting license zip data: %w", err)
	}

	reader, err := zip.NewReader(tmpPath, i.Size())
	if err != nil {
		return fmt.Errorf("creating zip reader: %w", err)
	}

	tmpdir, err := os.MkdirTemp("", "license-pack-")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	if err := os.MkdirAll(
		filepath.Join(tmpdir, "/json/details/"), fs.FileMode(0o755),
	); err != nil {
		return fmt.Errorf("creating license data dir: %w", err)
	}
	defer os.RemoveAll(tmpdir)

	zipFilePath := filepath.Join(license.EmbeddedDataDir, fmt.Sprintf("license-list-%s.zip", tag))
	zipFile, err := os.Create(zipFilePath)
	if err != nil {
		return fmt.Errorf("create zip file %q: %w", zipFilePath, err)
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)

	dirName := fmt.Sprintf("license-list-data-%s", strings.TrimPrefix(tag, "v"))
	if err := fs.WalkDir(reader, dirName, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walker got error: %w", err)
		}
		if d.IsDir() {
			return nil
		}

		if !strings.HasSuffix(path, "json/licenses.json") &&
			!strings.HasPrefix(path, filepath.Join(dirName, "json/details")) {
			return nil
		}

		logrus.Infof("writing %s", path)
		zipFileWriter, err := zipWriter.Create(path)
		if err != nil {
			return fmt.Errorf("creating file in zipfile: %w", err)
		}

		bs, err := fs.ReadFile(reader, path)
		if err != nil {
			return fmt.Errorf("reading filelicendse file from zip: %w", err)
		}

		if _, err := zipFileWriter.Write(bs); err != nil {
			return fmt.Errorf("error writing file %s: %w", path, err)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("walking license filesystem: %w", err)
	}
	zipWriter.Close()

	// patch the source to the new version
	data, err := os.ReadFile("pkg/license/catalog.go")
	if err != nil {
		return fmt.Errorf("reading catalog source: %w", err)
	}

	// Here, wee patch the catalog source to hardcode the version we
	// are embedding in the binary
	re := regexp.MustCompile(`Version: "v\d+\.\d+"`)
	data = re.ReplaceAll(data, []byte(fmt.Sprintf(`Version: "%s"`, tag)))
	if err := os.WriteFile("pkg/license/catalog.go", data, os.FileMode(0o644)); err != nil {
		return fmt.Errorf("unable to write catalog file: %w", err)
	}

	return nil
}
