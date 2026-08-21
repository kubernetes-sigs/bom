/*
Copyright 2026 The Kubernetes Authors.

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

package generate

import (
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// fileTypes derives the SPDX file type labels for a file, ported from
// the legacy generator: the extension decides, and files without one
// are classified by sniffing their content type.
func fileTypes(fsys fs.FS, name string) []string {
	ext := strings.TrimLeft(path.Ext(name), ".")
	if ext == "" {
		contentType, err := sniffContentType(fsys, name)
		if err != nil {
			return []string{"OTHER"}
		}
		parts := strings.SplitN(contentType, "/", 2)
		ext = parts[0]
		if parts[0] == "application" && len(parts) > 1 {
			ext = parts[1]
		}
	}

	switch ext {
	case "go", "java", "rs", "rb", "c", "cgi", "class", "cpp", "cs", "h",
		"php", "py", "sh", "swift", "vb", "css":
		return []string{"SOURCE"}
	case "txt", "text", "pdf", "md", "doc", "docx", "epub",
		"ppt", "pptx", "pps", "odp", "xls", "xlsm", "xlsx":
		return []string{"TEXT", "DOCUMENTATION"}
	case "yml", "yaml", "json":
		return []string{"TEXT"}
	case "exe", "a", "o", "octet-stream", "apk", "bat",
		"bin", "pl", "com", "gadget", "jar", "msi", "wsf":
		return []string{"BINARY", "APPLICATION"}
	case "jpeg", "jpg", "png", "svg", "ai", "bmp", "gif", "ico",
		"ps", "psd", "tif", "tiff":
		return []string{"IMAGE"}
	case "mp3", "wav", "aif", "cda", "mid", "midi",
		"mpa", "ogg", "wma", "wpl":
		return []string{"AUDIO"}
	case "zip", "tar", "gz", "bz2", "7z", "arj",
		"deb", "pkg", "rar", "rpm", "z", "cpio":
		return []string{"ARCHIVE"}
	default:
		return []string{"OTHER"}
	}
}

// sniffContentType detects a file's media type from its first 512
// bytes, the window http.DetectContentType uses.
func sniffContentType(fsys fs.FS, name string) (string, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return http.DetectContentType(buf[:n]), nil
}
