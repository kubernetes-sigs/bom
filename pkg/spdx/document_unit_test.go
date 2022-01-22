package spdx

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto"
	v02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/bom/pkg/provenance"
	"sigs.k8s.io/release-utils/hash"
)

func generateProvenanceSUT(t *testing.T) (doc *Document, tmpDir string) {
	s := NewSPDX()
	doc = NewDocument()
	tmpDir, err := os.MkdirTemp("", "test-files-")
	require.NoError(t, err)

	for i, d := range []string{"abc", "cde", "xyz"} {
		require.NoError(t, os.WriteFile(
			filepath.Join(tmpDir, fmt.Sprintf("file%d.txt", i)),
			[]byte(d), os.FileMode(0o644),
		))
		f, err := s.FileFromPath(filepath.Join(tmpDir, fmt.Sprintf("file%d.txt", i)))
		f.FileName = fmt.Sprintf("file%d.txt", i)
		require.NoError(t, err)
		require.NoError(t, doc.AddFile(f))
	}

	logrus.Infof("Files written to %s", tmpDir)

	return doc, tmpDir
}

func TestToProvenance(t *testing.T) {
	// Create a statement with the known digests
	statement := provenance.NewSLSAStatement()
	statement.Subject = append(statement.Subject,
		in_toto.Subject{
			Name: "file0.txt",
			Digest: v02.DigestSet{
				"sha1":   "a9993e364706816aba3e25717850c26c9cd0d89d",
				"sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
				"sha512": "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
			},
		},
		in_toto.Subject{
			Name: "file1.txt",
			Digest: v02.DigestSet{
				"sha1":   "5af13954a67eab2973b4ade01186602dd8739787",
				"sha256": "08a018a9549220d707e11c5c4fe94d8dd60825f010e71efaa91e5e784f364d7b",
				"sha512": "7c487d7160da126d2c7b4509cf72e90b5e35594d1ef10c5077c8a958e26201d18cdea513abfd5731ed4d43287cf0879c4515f59f3a03843141ca2bfc623719dd",
			},
		},
		in_toto.Subject{
			Name: "file2.txt",
			Digest: v02.DigestSet{
				"sha1":   "66b27417d37e024c46526c2f6d358a754fc552f3",
				"sha256": "3608bca1e44ea6c4d268eb6db02260269892c0b42b86bbf1e77a6fa16c3c9282",
				"sha512": "4a3ed8147e37876adc8f76328e5abcc1b470e6acfc18efea0135f983604953a58e183c1a6086e91ba3e821d926f5fdeb37761c7ca0328a963f5e92870675b728",
			},
		},
	)

	// Create a second statement by writing known files
	doc, tmpDir := generateProvenanceSUT(t)
	defer os.RemoveAll(tmpDir)

	statement2 := doc.ToProvenanceStatement(DefaultProvenanceOptions)

	// Compare the statements manually to ensure they are equivalent
	for _, s1 := range statement.Subject {
		for _, s2 := range statement2.Subject {
			if s1.Name == s2.Name {
				for _, algo := range []string{"sha1", "sha256", "sha512"} {
					require.Equal(
						t, s1.Digest[algo], s2.Digest[algo], fmt.Sprintf("matching %s hash in %s", algo, s1.Name),
					)
				}
			}
		}
	}
}

func TestWriteProvenance(t *testing.T) {
	doc, tmpDir := generateProvenanceSUT(t)
	defer os.RemoveAll(tmpDir)

	tfile, err := os.CreateTemp(tmpDir, "test-provenance-*.json")
	require.NoError(t, err)
	defer os.Remove(tfile.Name())
	// Write the peovenance
	require.NoError(t, doc.WriteProvenanceStatement(DefaultProvenanceOptions, tfile.Name()))
	s512, err := hash.SHA512ForFile(tfile.Name())
	require.NoError(t, err)
	require.Equal(t, "d877604a3f1abe9f339ce3de3ebde227f0d9626972387f62ee00951bd83bab12a59bbec3b440a0e74aab60263f4b1f80e8268e922d2dcf760980ed006149bf97", s512)
}
