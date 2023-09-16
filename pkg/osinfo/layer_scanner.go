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
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

type OSType string

const (
	OSAlpine      OSType = "alpine"
	OSAmazonLinux OSType = "amazonlinux"
	OSCentos      OSType = "centos"
	OSDebian      OSType = "debian"
	OSDistroless  OSType = "distroless"
	OSFedora      OSType = "fedora"
	OSRHEL        OSType = "rhel"
	OSUbuntu      OSType = "ubuntu"
	OSWolfi       OSType = "wolfi"

	dotSlash = "./"
)

// layerScanner is an interface to scan OCI image layers.
type layerScanner interface {
	OSType(layerPath string) (ostype OSType, err error)
	OSReleaseData(layerPath string) (osrelease string, err error)
	ExtractFileFromTar(tarPath, filePath, destPath string) error
	FileExistsInTar(tarPath, filePath string, moreFiles ...string) (bool, error)
	ExtractDirectoryFromTar(tarPath, dirName, destPath string) error
}

// newLayerScanner returns a LayerScanner.
func newLayerScanner() layerScanner {
	return &layerOSScanner{}
}

type layerOSScanner struct{}

func (loss *layerOSScanner) OSType(layerPath string) (ostype OSType, err error) {
	osrelease, err := loss.OSReleaseData(layerPath)
	if err != nil {
		if _, ok := err.(ErrFileNotFoundInTar); ok {
			return "", nil
		}
		if strings.Contains(err.Error(), "file not found") {
			return "", nil
		}
		return "", fmt.Errorf("reading os release: %w", err)
	}

	if osrelease == "" {
		return "", nil
	}

	logrus.Debugf("OS Info Contents:\n%s", osrelease)
	// The distroless identifier is in the PRETTY_NAME field and the
	// distro on which it is based is in NAME, hence we need to catch
	// the distroless moniker before reading the name.
	if strings.Contains(osrelease, "PRETTY_NAME=\"Distroless") {
		logrus.Infof("Scan of container layers found %s base image", OSDistroless)
		return OSDistroless, nil
	}

	if strings.Contains(osrelease, "NAME=\"Debian GNU") {
		logrus.Infof("Scan of container layers found %s base image", OSDebian)
		return OSDebian, nil
	}

	if strings.Contains(osrelease, "NAME=\"Ubuntu\"") {
		return OSUbuntu, nil
	}

	if strings.Contains(osrelease, "NAME=\"Fedora Linux\"") {
		return OSFedora, nil
	}

	if strings.Contains(osrelease, "NAME=\"CentOS Linux\"") {
		return OSCentos, nil
	}

	if strings.Contains(osrelease, "NAME=\"Red Hat Enterprise Linux\"") {
		return OSRHEL, nil
	}

	if strings.Contains(osrelease, "NAME=\"Alpine Linux\"") {
		return OSAlpine, nil
	}

	if strings.Contains(osrelease, "NAME=\"Wolfi\"") {
		return OSWolfi, nil
	}

	if strings.Contains(osrelease, `NAME="Amazon Linux"`) {
		return OSAmazonLinux, nil
	}

	return "", nil
}

// OSReleaseData extracts the OS release file and returns it as a string
func (loss *layerOSScanner) OSReleaseData(layerPath string) (osrelease string, err error) {
	f, err := os.CreateTemp("", "os-release-")
	if err != nil {
		return osrelease, fmt.Errorf("creating temp file: %w", err)
	}
	defer f.Close()
	defer os.Remove(f.Name())

	destPath := f.Name()

	// Exxtrac the  os-release file
	err = loss.ExtractFileFromTar(layerPath, OsReleasePath, destPath)

	// but if not found, try the alternativepath. In distroless, it gets
	// rewritten in later layers, but the /etc symlink remains unmodified
	if err != nil && errors.Is(err, ErrFileNotFoundInTar{}) {
		err = loss.ExtractFileFromTar(layerPath, AltOSReleasePath, destPath)
	}

	if err != nil {
		return "", fmt.Errorf("extracting os-release from tar: %w", err)
	}

	data, err := os.ReadFile(destPath)
	if err != nil {
		return osrelease, fmt.Errorf("reading osrelease: %w", err)
	}
	return string(data), nil
}

type ErrFileNotFoundInTar struct{}

func (e ErrFileNotFoundInTar) Error() string {
	return "file not found in tarball"
}

// FileExistsInTar finds a file in a tarball.
func (loss *layerOSScanner) FileExistsInTar(tarPath, firstFile string, moreFiles ...string) (bool, error) {
	// Open the tar file
	f, err := os.Open(tarPath)
	if err != nil {
		return false, fmt.Errorf("opening tarball: %w", err)
	}
	defer f.Close()

	tr, err := getTarReader(f)
	if err != nil {
		return false, fmt.Errorf("building tar reader: %w", err)
	}

	filesDict := map[string]struct{}{
		firstFile: {},
	}

	for _, f := range moreFiles {
		filesDict[f] = struct{}{}
	}

	// Search for the file in the tar contents
	for {
		hdr, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				return false, nil
			}
			return false, fmt.Errorf("reading tarfile: %w", err)
		}

		if hdr.FileInfo().IsDir() {
			continue
		}

		// Scan for the os-release file in the tarball
		if _, ok := filesDict[strings.TrimPrefix(hdr.Name, dotSlash)]; !ok {
			continue
		}

		filePath := strings.TrimPrefix(hdr.Name, dotSlash)
		// If this is a symlink, follow:
		if hdr.FileInfo().Mode()&os.ModeSymlink == os.ModeSymlink {
			target := hdr.Linkname
			// Check if its relative:
			if !strings.HasPrefix(target, string(filepath.Separator)) {
				newTarget := filepath.Dir(filePath)

				//nolint:gosec // This is not zipslip, path it not used for writing just
				// to search a file in the tarfile, the extract path is fexed.
				newTarget = filepath.Join(newTarget, hdr.Linkname)
				target = filepath.Clean(newTarget)
			}
			logrus.Infof("%s is a symlink, following to %s", filePath, target)
			return loss.FileExistsInTar(tarPath, target)
		}
		return true, nil
	}
}

// getTarReader builds a tar reader to process a tar stream from the reader r
func getTarReader(r io.ReadSeeker) (*tar.Reader, error) {
	// Read the first bytes to determine if the file is compressed
	gzipped, err := isStreamCompressed(r)
	if err != nil {
		return nil, fmt.Errorf("checking file compression: %w", err)
	}

	var tr *tar.Reader
	tr = tar.NewReader(r)
	if gzipped {
		gzf, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("creating gzip reader: %w", err)
		}
		tr = tar.NewReader(gzf)
	}

	return tr, nil
}

// extractFileFromTar extracts filePath from tarPath and stores it in destPath
func (loss *layerOSScanner) ExtractFileFromTar(tarPath, filePath, destPath string) error {
	// Open the tar file
	f, err := os.Open(tarPath)
	if err != nil {
		return fmt.Errorf("opening tarball: %w", err)
	}
	defer f.Close()

	tr, err := getTarReader(f)
	if err != nil {
		return fmt.Errorf("building tar reader: %w", err)
	}

	// Search for the os-file in the tar contents
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return ErrFileNotFoundInTar{}
		}
		if err != nil {
			return fmt.Errorf("reading tarfile: %w", err)
		}

		if hdr.FileInfo().IsDir() {
			continue
		}

		if strings.TrimPrefix(hdr.Name, dotSlash) != strings.TrimPrefix(filePath, dotSlash) {
			continue
		}

		// If this is a symlink, follow:
		if hdr.FileInfo().Mode()&os.ModeSymlink == os.ModeSymlink {
			target := hdr.Linkname
			// Check if its relative:
			if !strings.HasPrefix(target, string(filepath.Separator)) {
				newTarget := filepath.Dir(filePath)

				//nolint:gosec // This is not zipslip, path it not used for writing just
				// to search a file in the tarfile, the extract path is fexed.
				newTarget = filepath.Join(newTarget, hdr.Linkname)
				target = filepath.Clean(newTarget)
			}
			logrus.Debugf("%s is a symlink, following to %s", filePath, target)
			return loss.ExtractFileFromTar(tarPath, target, destPath)
		}

		// Open the destination file
		destPointer, err := os.Create(destPath)
		if err != nil {
			return fmt.Errorf("opening destination file: %w", err)
		}
		defer destPointer.Close()

		for {
			if _, err = io.CopyN(destPointer, tr, 1024); err != nil {
				if err == io.EOF {
					return nil
				}
				return fmt.Errorf("writing data to %s: %w", destPath, err)
			}
		}
	}
}

// isFileCompressed returns true if the reader
func isStreamCompressed(r io.ReadSeeker) (bool, error) {
	var sample [3]byte
	if _, err := io.ReadFull(r, sample[:]); err != nil {
		return false, fmt.Errorf("sampling bytes from file header: %w", err)
	}
	if _, err := r.Seek(0, 0); err != nil {
		return false, fmt.Errorf("rewinding read pointer: %w", err)
	}

	// From: https://github.com/golang/go/blob/1fadc392ccaefd76ef7be5b685fb3889dbee27c6/src/compress/gzip/gunzip.go#L185
	if sample[0] == 0x1f && sample[1] == 0x8b && sample[2] == 0x08 {
		return true, nil
	}
	return false, nil
}

// ExtractDirectoryFromTar extracts all files from a tarball that match the
// dirName into destPath
func (loss *layerOSScanner) ExtractDirectoryFromTar(tarPath, dirName, destPath string) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return fmt.Errorf("opening tarball: %w", err)
	}
	defer f.Close()

	tr, err := getTarReader(f)
	if err != nil {
		return fmt.Errorf("building tar reader: %w", err)
	}

	foundSomeFiles := false

	// Search for the os-file in the tar contents
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			if foundSomeFiles {
				return nil
			}
			return ErrFileNotFoundInTar{}
		}
		if err != nil {
			return fmt.Errorf("reading tarfile: %w", err)
		}

		if hdr.FileInfo().IsDir() {
			continue
		}

		if hdr.FileInfo().Mode()&os.ModeSymlink == os.ModeSymlink {
			continue
		}

		// If the current file is not in the target dir, skip
		filePath := strings.TrimPrefix(hdr.Name, dotSlash)
		if !strings.HasPrefix(filePath, dirName) {
			continue
		}

		foundSomeFiles = true

		// Open the destination file
		realPath := filepath.Join(destPath, filePath)
		if err := os.MkdirAll(filepath.Dir(realPath), os.FileMode(0o755)); err != nil {
			return fmt.Errorf("creating extraction directory for %s: %w", filePath, err)
		}
		destPointer, err := os.Create(realPath)
		if err != nil {
			return fmt.Errorf(
				"opening destination file in %s: %w", realPath, err,
			)
		}
		defer destPointer.Close()

		for {
			if _, err = io.CopyN(destPointer, tr, 1024); err != nil {
				if err != io.EOF {
					return fmt.Errorf("writing data to %s: %w", destPath, err)
				}
				break
			}
		}
	}
}
