package spdx

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto"
	v02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/bom/pkg/provenance"
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

// testStatement returns a predictable statement that we can use to
// compare generating functions
func testStatement() *provenance.Statement {
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
	return statement
}

func TestToProvenance(t *testing.T) {
	// Create a second statement by writing known files
	doc, tmpDir := generateProvenanceSUT(t)
	defer os.RemoveAll(tmpDir)

	statement := doc.ToProvenanceStatement(DefaultProvenanceOptions)
	compareSubjects(t, testStatement(), statement)
}

func TestWriteProvenance(t *testing.T) {
	doc, tmpDir := generateProvenanceSUT(t)
	defer os.RemoveAll(tmpDir)

	tfile, err := os.CreateTemp("", "test-provenance-*.json")
	require.NoError(t, err)
	defer os.Remove(tfile.Name())

	// Write the provenance to a file
	require.NoError(t, doc.WriteProvenanceStatement(DefaultProvenanceOptions, tfile.Name()))
	require.NoError(t, err)

	// Now, read it back and compare to what we know
	data, err := os.ReadFile(tfile.Name())
	require.NoError(t, err)
	statement1 := &provenance.Statement{}
	require.NoError(t, json.Unmarshal(data, statement1))

	compareSubjects(t, statement1, testStatement())
}

// This function gets two provenance statements and checks their
// subjects to be equivalent, returning an error if they do not match
func compareSubjects(t *testing.T, statement1, statement2 *provenance.Statement) {
	require.Equal(t, len(statement1.Subject), len(statement2.Subject))
	// Compare the statements manually to ensure they are equivalent
	for _, s1 := range statement1.Subject {
		for _, s2 := range statement2.Subject {
			require.Equal(t, len(s1.Digest), len(s2.Digest))
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

func TestEnsureUniqueElementID(t *testing.T) {
	doc := NewDocument()
	name := "same-name"
	for i := 0; i < 3; i++ {
		subp := NewPackage()
		subp.SetSPDXID(name)

		// Passing the subpackages through nsureUniquePackageID
		// should rename the last two, but not the first one
		doc.ensureUniqueElementID(subp)
		require.NoError(t, doc.AddPackage(subp))

		if i == 0 {
			require.Equal(t, name, subp.SPDXID())
		} else {
			require.NotEqual(t, name, subp.SPDXID())
		}
	}
}

func TestEnsureUniquePeerIDs(t *testing.T) {
	doc := NewDocument()
	name := "same-name"

	// Add one node with the name
	namePkg := NewPackage()
	namePkg.SetSPDXID(name)

	// Build a package with 3 peers all with the same name
	p := NewPackage()
	p.SetSPDXID("parentNode")
	for i := 0; i < 3; i++ {
		subp := NewPackage()
		subp.SetSPDXID(name)
		require.NoError(t, p.AddPackage(subp))
	}

	// Pass the package with its peers through ensureUniquePeerIDs
	doc.ensureUniquePeerIDs(p.GetRelationships())

	// Now, they should all be different
	seenNames := map[string]struct{}{}
	rels := p.GetRelationships()
	for _, rel := range *rels {
		logrus.Info("Checking " + rel.Peer.SPDXID())
		_, ok := seenNames[rel.Peer.SPDXID()]
		require.False(t, ok, rel.Peer.SPDXID()+" should be unique")
		seenNames[rel.Peer.SPDXID()] = struct{}{}
	}
}

func TestValidateFiles(t *testing.T) {
	type fileMap struct {
		shouldFail bool
		path       string
		data       string
		hashes     map[string]string
	}
	type testCase struct {
		files []fileMap
	}

	for _, tc := range []testCase{
		{
			files: []fileMap{
				{false, "", "abc", map[string]string{"SHA256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}},
			},
		},
		{
			// Unsupprted algo
			files: []fileMap{
				{true, "", "abc", map[string]string{"MD5": "900150983cd24fb0d6963f7d28e17f72"}},
			},
		},
		{
			// Two supported algos, both correct
			files: []fileMap{
				{false, "", "abc", map[string]string{
					"SHA256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
					"SHA512": "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
				}},
			},
		},
		{
			// Two supported algos, one wrong
			files: []fileMap{
				{true, "", "abc", map[string]string{
					"SHA256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
					"SHA512": "WRONGdaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
				}},
			},
		},
		{
			// No validation
			files: []fileMap{
				{true, "", "abc", map[string]string{}},
			},
		},
	} {
		doc := NewDocument()
		doc.Name = "test"
		filePaths := []string{}
		for i, fm := range tc.files {
			temp, err := os.CreateTemp("", "verify")
			require.NoError(t, err)
			defer os.Remove(temp.Name())
			require.NoError(t, os.WriteFile(temp.Name(), []byte(fm.data), os.FileMode(0o644)))
			tc.files[i].path = temp.Name()
			filePaths = append(filePaths, temp.Name())

			f := NewFile()
			f.Name = temp.Name()
			f.FileName = temp.Name()

			f.Checksum = fm.hashes
			require.NoError(t, doc.AddFile(f))
		}

		// Now cycle and check each
		resData, err := doc.ValidateFiles(filePaths)
		require.NoError(t, err)
		logrus.Infof("%+v", resData)
		for _, fdata := range tc.files {
			require.NotEmpty(t, fdata.path)
			found := false
			for _, res := range resData {
				if fdata.path == res.FileName {
					require.Equal(t, !fdata.shouldFail, res.Success, "file: "+res.FileName)
					found = true
				}
			}
			require.True(t, found)
		}
	}

	// Validating a non existent files must fail
	doc := NewDocument()
	doc.Name = "lkajlk"
	f := NewFile()
	f.Name = "laksjdl"
	require.NoError(t, doc.AddFile(f))
	_, err := doc.ValidateFiles([]string{"/tmo/lskdjflskdjf"})
	require.Error(t, err)
}
