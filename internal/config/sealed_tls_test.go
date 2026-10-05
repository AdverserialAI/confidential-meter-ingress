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
}

func TestSealedTLSRejectsPartialBundle(t *testing.T) {
	t.Setenv("TLS_CERT_PEM_B64", "c2VydmVy")
	if err := MaterializeSealedTLSFromEnv(); err == nil {
		t.Fatal("partial bundle was accepted")
	}
}
