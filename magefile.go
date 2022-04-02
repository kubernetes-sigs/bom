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
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/carolynvs/magex/pkg"
	"github.com/carolynvs/magex/pkg/archive"
	"github.com/carolynvs/magex/pkg/downloads"
	"github.com/magefile/mage/sh"
	"github.com/pkg/errors"

	"sigs.k8s.io/release-utils/mage"
)

// Default target to run when none is specified
// If not set, running mage will list available targets
var Default = Verify

const (
	binDir    = "bin"
	scriptDir = "scripts"
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
	if err := mage.RunGolangCILint("v1.44.2", false); err != nil {
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
	if err := EnsureKO(""); err != nil {
		return err
	}

	os.Setenv("BOM_LDFLAGS", generateLDFlags())
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

	if err := EnsureKO(""); err != nil {
		return err
	}

	if err := Build(); err != nil {
		return errors.Wrap(err, "building the binaries")
	}

	if err := BuildImages(); err != nil {
		return errors.Wrap(err, "building the images")
	}

	// if err := sh.RunV("cd", "output"); err != nil {
	// 	return errors.Wrap(err, "cd into output directory")
	// }

	// if err := sh.RunV("./bom-linux-amd64", "output", "generate", "-f", "bom-darwin-amd64",
	// 	"-f", "bom-darwin-arm64", "-f", "bom-linux-amd64", "-f", "bom-linux-arm64",
	// 	"-f", "bom-windows-amd64.exe", "-d", "../", "-o", "bom-sbom.sdpx"); err != nil {
	// 	return errors.Wrap(err, "generating the bom")
	// }

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

func generateLDFlags() string {
	pkg := "sigs.k8s.io/bom/pkg/version"
	return fmt.Sprintf("-X %[1]s.GitVersion=%[2]s -X %[1]s.gitCommit=%[3]s -X %[1]s.gitTreeState=%[4]s -X %[1]s.buildDate=%[5]s", pkg, getVersion(), getCommit(), getGitState(), getBuildDateTime())
}

// Maybe we can  move this to release-utils
func EnsureKO(version string) error {
	versionToInstall := version
	if versionToInstall == "" {
		versionToInstall = "0.11.2"
	}

	fmt.Printf("Checking if `ko` version %s is installed\n", versionToInstall)
	found, err := pkg.IsCommandAvailable("ko", versionToInstall, "version")
	if err != nil {
		return err
	}

	if !found {
		fmt.Println("`ko` not found")
		return InstallKO(versionToInstall)
	}

	fmt.Println("`ko` is installed!")
	return nil
}

// Maybe we can  move this to release-utils
func InstallKO(version string) error {
	fmt.Println("Will install `ko`")
	target := "ko"
	if runtime.GOOS == "windows" {
		target = "ko.exe"
	}

	opts := archive.DownloadArchiveOptions{
		DownloadOptions: downloads.DownloadOptions{
			UrlTemplate: "https://github.com/google/ko/releases/download/v{{.VERSION}}/ko_{{.VERSION}}_{{.GOOS}}_{{.GOARCH}}{{.EXT}}",
			Name:        "ko",
			Version:     version,
			OsReplacement: map[string]string{
				"darwin":  "Darwin",
				"linux":   "Linux",
				"windows": "Windows",
			},
			ArchReplacement: map[string]string{
				"amd64": "x86_64",
			},
		},
		ArchiveExtensions: map[string]string{
			"linux":   ".tar.gz",
			"darwin":  ".tar.gz",
			"windows": ".tar.gz",
		},
		TargetFileTemplate: target,
	}

	return archive.DownloadToGopathBin(opts)
}
