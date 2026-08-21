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

package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"sigs.k8s.io/release-utils/helpers"
	"sigs.k8s.io/release-utils/version"

	"sigs.k8s.io/bom/pkg/license"
	"sigs.k8s.io/bom/pkg/serialize"
	"sigs.k8s.io/bom/pkg/spdx"
)

type generateOptions struct {
	analyze        bool
	noGitignore    bool
	noGoModules    bool
	noGoTransient  bool
	offline        bool
	scanImages     bool
	name           string // Name to use in the document
	namespace      string
	format         string
	outputFile     string
	configFile     string
	license        string
	licenseListVer string
	provenancePath string // Path to export the SBOM as provenance statement
	images         []string
	imageArchives  []string
	archives       []string
	files          []string
	directories    []string
	ignorePatterns []string
}

// Validate verify options consistency.
func (opts *generateOptions) Validate() error {
	if opts.configFile == "" &&
		len(opts.images) == 0 &&
		len(opts.files) == 0 &&
		len(opts.imageArchives) == 0 &&
		len(opts.archives) == 0 &&
		len(opts.directories) == 0 {
		return errors.New("to generate a SPDX BOM you have to provide at least one image or file")
	}

	if opts.format != spdx.FormatTagValue && opts.format != spdx.FormatJSON {
		return fmt.Errorf("unknown format provided, must be one of [%s, %s]: %s",
			spdx.FormatTagValue, spdx.FormatJSON, opts.format)
	}

	// Check if specified local files exist
	for _, col := range []struct {
		Items []string
		Name  string
	}{
		{opts.imageArchives, "image archive"},
		{opts.files, "file"},
		{opts.directories, "directory"},
		{opts.archives, "archive"},
	} {
		// Check if image archives exist
		for i, iPath := range col.Items {
			if !isGlob(iPath) && !helpers.Exists(iPath) {
				return fmt.Errorf("%s #%d not found (%s)", col.Name, i+1, iPath)
			}
		}
	}
	return nil
}

func isGlob(pathPattern string) bool {
	return strings.ContainsAny(pathPattern, "*?")
}

func AddGenerate(parent *cobra.Command) {
	genOpts := &generateOptions{}

	generateCmd := &cobra.Command{
		Short: "bom generate → Create SPDX SBOMs",
		Long: `bom generate → Create SPDX SBOMs

generate is the bom subcommand to generate SPDX manifests.

Currently supports creating SBOM from files, images, and docker
archives (images in tarballs). It supports pulling images from
remote registries for analysis.

bom can take a deeper look into images using a growing number
of analyzers designed to add more sense to common base images.

The SBOM data can also be exported to an in-toto provenance
attestation. The output will produce a provenance statement listing all
the SPDX data as in-toto subjects, but otherwise ready to be
completed by a later stage in your CI/CD pipeline. See the
--provenance flag for more details.

`,
		Use:               "generate",
		SilenceUsage:      true,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		RunE: func(cmd *cobra.Command, args []string) error {
			warnRetiredFlags(cmd)

			for i, arg := range args {
				if !helpers.Exists(arg) {
					continue
				}
				file, err := os.Open(arg)
				if err != nil {
					return fmt.Errorf("checking argument %d: %w", i, err)
				}
				fileInfo, err := file.Stat()
				if err != nil {
					return fmt.Errorf("calling stat on argument %d: %w", i, err)
				}
				if fileInfo.IsDir() {
					genOpts.directories = append(genOpts.directories, arg)
				}
			}

			if err := genOpts.Validate(); err != nil {
				cmd.Help() //nolint:errcheck // We already errored
				return fmt.Errorf("validating command line options: %w", err)
			}

			return generateBOM(genOpts)
		},
	}

	generateCmd.PersistentFlags().StringSliceVarP(
		&genOpts.images,
		"image",
		"i",
		[]string{},
		"list of images",
	)

	generateCmd.PersistentFlags().StringSliceVarP(
		&genOpts.files,
		"file",
		"f",
		[]string{},
		"list of files to include",
	)

	generateCmd.PersistentFlags().StringSliceVarP(
		&genOpts.imageArchives,
		"tarball",
		"t",
		[]string{},
		"list of docker archive tarballs to include in the manifest",
	)

	if err := generateCmd.PersistentFlags().MarkDeprecated(
		"tarball", "tarball has been renamed to image-archive",
	); err != nil {
		logrus.Fatalf("marking flag as deprecated: %v", err)
	}

	generateCmd.PersistentFlags().StringSliceVar(
		&genOpts.imageArchives,
		"image-archive",
		[]string{},
		"list of docker archive tarballs to include in the manifest",
	)

	generateCmd.PersistentFlags().StringSliceVar(
		&genOpts.archives,
		"archive",
		[]string{},
		"list of archives to add as packages (supports tar, tar.gz)",
	)

	generateCmd.PersistentFlags().StringSliceVarP(
		&genOpts.directories,
		"dirs",
		"d",
		[]string{},
		"list of directories to include in the manifest as packages",
	)

	generateCmd.PersistentFlags().StringSliceVar(
		&genOpts.ignorePatterns,
		"ignore",
		[]string{},
		"list of regexp patterns to ignore when scanning directories",
	)

	generateCmd.PersistentFlags().StringVarP(
		&genOpts.license,
		"license",
		"l",
		"",
		"SPDX license identifier to declare in the SBOM",
	)

	generateCmd.PersistentFlags().BoolVar(
		&genOpts.noGitignore,
		"no-gitignore",
		false,
		"don't use exclusions from .gitignore files",
	)

	generateCmd.PersistentFlags().BoolVar(
		&genOpts.noGoModules,
		"no-gomod",
		false,
		"don't perform go.mod analysis, sbom will not include data about go packages",
	)

	generateCmd.PersistentFlags().BoolVar(
		&genOpts.noGoTransient,
		"no-transient",
		false,
		"don't resolve dependencies beyond those a codebase requires in its go.mod",
	)

	generateCmd.PersistentFlags().BoolVar(
		&genOpts.offline,
		"offline",
		false,
		"don't reach the network: dependency data is read from local files only",
	)

	generateCmd.PersistentFlags().StringVarP(
		&genOpts.namespace,
		"namespace",
		"n",
		"",
		"an URI that serves as namespace for the SPDX doc",
	)

	generateCmd.PersistentFlags().StringVar(
		&genOpts.format,
		"format",
		spdx.FormatJSON,
		fmt.Sprintf("format of the document (supports %s, %s)",
			spdx.FormatJSON, spdx.FormatTagValue),
	)

	generateCmd.PersistentFlags().StringVarP(
		&genOpts.outputFile,
		"output",
		"o",
		"",
		"path to the file where the document will be written (defaults to STDOUT)",
	)

	generateCmd.PersistentFlags().BoolVarP(
		&genOpts.analyze,
		"analyze-images",
		"a",
		false,
		"go deeper into images using the available analyzers",
	)

	generateCmd.PersistentFlags().StringVarP(
		&genOpts.configFile,
		"config",
		"c",
		"",
		"path to yaml SBOM configuration file",
	)

	generateCmd.PersistentFlags().StringVar(
		&genOpts.provenancePath,
		"provenance",
		"",
		"path to export the SBOM as an in-toto provenance statement",
	)

	generateCmd.PersistentFlags().BoolVar(
		&genOpts.scanImages,
		"scan-images",
		true,
		"scan container images to look for OS information (currently debian, alpine, and rpm only)",
	)

	generateCmd.PersistentFlags().StringVar(
		&genOpts.name,
		"name",
		"",
		"name for the document, in contrast to URLs, intended for humans",
	)

	generateCmd.PersistentFlags().StringVar(
		&genOpts.licenseListVer,
		"license-list-version",
		license.DefaultCatalogOpts.Version,
		"version of the SPDX list to use (or 'latest')",
	)

	if err := generateCmd.MarkPersistentFlagDirname("dirs"); err != nil {
		logrus.Error("error marking flag as directory")
	}
	for _, fl := range []string{"config", "image-archive", "file", "archive"} {
		if err := generateCmd.MarkPersistentFlagFilename(fl); err != nil {
			logrus.Error("error marking flag as file")
		}
	}

	// Flags describing choices the generation engine no longer offers.
	// They are still accepted so existing invocations keep working.
	for _, name := range retiredFlags {
		if err := generateCmd.PersistentFlags().MarkHidden(name); err != nil {
			logrus.Debugf("hiding %s: %v", name, err)
		}
	}

	parent.AddCommand(generateCmd)
}

// retiredFlags name options the generation engine no longer honors.
// Scanning images and resolving a codebase's dependencies are now part
// of every run, deep image layer analysis has no equivalent, and the
// document license was never applied. They stay accepted, and hidden,
// so existing invocations keep working.
var retiredFlags = []string{"license", "no-gomod", "scan-images", "analyze-images"}

// warnRetiredFlags tells the caller when they asked for something that
// no longer has an effect, rather than silently ignoring it.
//
// analyze-images is left out: the document builder warns about it
// already, which also reaches callers using the package directly.
func warnRetiredFlags(cmd *cobra.Command) {
	for _, name := range retiredFlags {
		if name == "analyze-images" {
			continue
		}
		if cmd.Flags().Changed(name) {
			logrus.Warnf("--%s is no longer supported and has no effect", name)
		}
	}
}

func generateBOM(opts *generateOptions) error {
	logrus.Infof(
		"bom %s: Generating SPDX Bill of Materials",
		version.GetVersionInfo().GitVersion,
	)

	newDocBuilderOpts := []spdx.NewDocBuilderOption{spdx.WithFormat(spdx.Format(opts.format))}
	builder := spdx.NewDocBuilder(newDocBuilderOpts...)
	builderOpts := &spdx.DocGenerateOptions{
		Tarballs:           opts.imageArchives,
		Archives:           opts.archives,
		Files:              opts.files,
		Images:             opts.images,
		Directories:        opts.directories,
		Format:             opts.format,
		OutputFile:         opts.outputFile,
		Namespace:          opts.namespace,
		AnalyseLayers:      opts.analyze,
		ProcessGoModules:   !opts.noGoModules,
		NoGitignore:        opts.noGitignore,
		Offline:            opts.offline,
		OnlyDirectDeps:     opts.noGoTransient,
		ConfigFile:         opts.configFile,
		License:            opts.license,
		LicenseListVersion: opts.licenseListVer,
		ScanImages:         opts.scanImages,
		Name:               opts.name,
	}

	// We only replace the ignore patterns one or more where defined
	if len(opts.ignorePatterns) > 0 {
		builderOpts.IgnorePatterns = opts.ignorePatterns
	}
	doc, err := builder.Generate(builderOpts)
	if err != nil {
		return fmt.Errorf("generating doc: %w", err)
	}

	var renderer serialize.Serializer
	if opts.format == "json" {
		renderer = &serialize.JSON{}
	} else {
		renderer = &serialize.TagValue{}
	}

	markup, err := renderer.Serialize(doc)
	if err != nil {
		return fmt.Errorf("serializing document: %w", err)
	}
	if opts.outputFile == "" {
		fmt.Println(markup)
	} else {
		if err := os.WriteFile(opts.outputFile, []byte(markup), 0o664); err != nil { //nolint:gosec // G306: Expect WriteFile
			return fmt.Errorf("writing SBOM: %w", err)
		}
	}
	// Export the SBOM as in-toto provenance
	if opts.provenancePath != "" {
		if err := doc.WriteProvenanceStatement(
			spdx.DefaultProvenanceOptions, opts.provenancePath,
		); err != nil {
			return fmt.Errorf("writing SBOM as provenance statement: %w", err)
		}
	}

	return nil
}
