package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestMaterializeSealedTLSFromEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TLS_MATERIAL_DIR", dir)
	t.Setenv("TLS_CERT_PEM_B64", base64.StdEncoding.EncodeToString([]byte("-----BEGIN CERTIFICATE-----\nserver\n-----END CERTIFICATE-----\n")))
	t.Setenv("TLS_KEY_PEM_B64", base64.StdEncoding.EncodeToString([]byte("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n")))
	t.Setenv("CLIENT_CA_PEM_B64", base64.StdEncoding.EncodeToString([]byte("-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n")))
	if err := MaterializeSealedTLSFromEnv(); err != nil {
		t.Fatal(err)
	}
	for _, variable := range []string{"TLS_CERT_FILE", "TLS_KEY_FILE", "CLIENT_CA_FILE"} {
		path := os.Getenv(variable)
		if filepath.Dir(path) != dir {
			t.Fatalf("%s path %q is outside private dir", variable, path)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v, err = %v", variable, info.Mode(), err)
		}
	}
	for _, variable := range []string{"TLS_CERT_PEM_B64", "TLS_KEY_PEM_B64", "CLIENT_CA_PEM_B64"} {
		if value := os.Getenv(variable); value != "" {
			t.Fatalf("%s remains in the process environment", variable)
		}
	}
}

func TestSealedTLSRejectsPartialBundle(t *testing.T) {
	t.Setenv("TLS_CERT_PEM_B64", "c2VydmVy")
	if err := MaterializeSealedTLSFromEnv(); err == nil {
		t.Fatal("partial bundle was accepted")
	}
}

func TestSealedTLSRejectsSymlinkedMaterialDirectory(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "tls-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TLS_MATERIAL_DIR", link)
	t.Setenv("TLS_CERT_PEM_B64", base64.StdEncoding.EncodeToString([]byte("-----BEGIN CERTIFICATE-----\nserver\n-----END CERTIFICATE-----\n")))
	t.Setenv("TLS_KEY_PEM_B64", base64.StdEncoding.EncodeToString([]byte("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n")))
	t.Setenv("CLIENT_CA_PEM_B64", base64.StdEncoding.EncodeToString([]byte("-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n")))
	if err := MaterializeSealedTLSFromEnv(); err == nil {
		t.Fatal("symlinked TLS_MATERIAL_DIR was accepted")
	}
}
