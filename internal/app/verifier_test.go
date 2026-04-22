package app

import (
	_ "embed"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed sigstage.root.json
var sigstageRoot []byte

func TestLoadVerifiers_DefaultTrustDomain(t *testing.T) {
	// When no trust domains are provided, it should default to "dotcom"
	verifiers, err := LoadVerifiers(false, nil)
	require.NoError(t, err)
	assert.Len(t, verifiers, 1, "expected one GH verifier for default dotcom domain")
}

func TestLoadVerifiers_WithPGI(t *testing.T) {
	verifiers, err := LoadVerifiers(true, nil)
	require.NoError(t, err)
	assert.Len(t, verifiers, 2, "expected PGI + GH dotcom verifiers")
}

func TestLoadVerifiers_WithPGIAndDomains(t *testing.T) {
	verifiers, err := LoadVerifiers(true, []string{"dotcom"})
	require.NoError(t, err)
	// 1 PGI + 1 GH
	assert.Len(t, verifiers, 2)
}

func TestLoadVerifiers_MultipleDomains(t *testing.T) {
	verifiers, err := LoadVerifiers(false, []string{"dotcom"})
	require.NoError(t, err)
	assert.Len(t, verifiers, 1, "expected one GH verifier per trust domain")
}

func TestLoadVerifiers_MultipleDomainsWithProdSDC(t *testing.T) {
	verifiers, err := LoadVerifiers(false, []string{"dotcom", "prod-sdc-01"})
	require.NoError(t, err)
	assert.Len(t, verifiers, 2, "expected one GH verifier per trust domain")
}

func TestLoadVerifiers_InvalidDomain(t *testing.T) {
	_, err := LoadVerifiers(false, []string{"nonexistent"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load GitHub verifier")
}

func TestLoadCustomVerifier_EmptyTrustDomains(t *testing.T) {
	// Even with valid repo/root args, empty tds should return an error
	tmpDir := t.TempDir()
	rootFile := filepath.Join(tmpDir, "root.json")
	require.NoError(t, os.WriteFile(rootFile, []byte(`{}`), 0o600))

	verifiers, err := LoadCustomVerifier("https://example.com", rootFile, nil)
	require.Error(t, err)
	assert.Nil(t, verifiers)
	assert.Contains(t, err.Error(), "no trust root provided")
}

func TestLoadCustomVerifier_BadRootPath(t *testing.T) {
	verifiers, err := LoadCustomVerifier("https://example.com", "/nonexistent/root.json", []string{"td1"})
	require.Error(t, err)
	assert.Nil(t, verifiers)
	assert.Contains(t, err.Error(), "failed to load verifier")
}

func TestLoadCustomVerifier_InvalidRoot(t *testing.T) {
	tmpDir := t.TempDir()
	rootFile := filepath.Join(tmpDir, "root.json")
	require.NoError(t, os.WriteFile(rootFile, []byte(`not valid json`), 0o600))

	verifiers, err := LoadCustomVerifier("https://example.com", rootFile, []string{"td1"})
	require.Error(t, err)
	assert.Nil(t, verifiers)
	assert.Contains(t, err.Error(), "failed to create verifier")
}

func TestCreateVerifier_AllFour(t *testing.T) {
	// Write the embedded sigstage root to a temp file for LoadCustomVerifier
	tmpDir := t.TempDir()
	rootFile := filepath.Join(tmpDir, "sigstage.root.json")
	require.NoError(t, os.WriteFile(rootFile, sigstageRoot, 0o600))

	cfg := &VerifierCfg{
		UsePGI:       true,
		TrustDomains: []string{"dotcom", "prod-sdc-01"},
		TufRepo:      "https://tuf-repo-cdn.sigstage.dev",
		TufRoot:      rootFile,
		TufTargets:   []string{"trusted_root.json"},
	}

	mv, err := CreateVerifier(cfg)
	require.NoError(t, err)
	// 1 custom (sigstage) + 1 PGI + 2 GH (dotcom + prod-sdc-01) = 4
	assert.Len(t, mv.V, 4)
}
