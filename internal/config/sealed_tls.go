package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// MaterializeSealedTLSFromEnv writes the three PEM values supplied through a
// sealed environment into private, ephemeral files and points the ordinary
// file-based configuration at them. It is intentionally all-or-nothing: a
// partially supplied bundle or a mixture with file paths refuses to start.
//
// This lets a confidential VM use its native sealed-environment mechanism
// without placing an mTLS private key in an image, repository, or host volume.
func MaterializeSealedTLSFromEnv() error {
	type field struct {
		encoded string
		path    string
		name    string
		marker  string
	}
	fields := []field{
		{encoded: "TLS_CERT_PEM_B64", path: "TLS_CERT_FILE", name: "server.crt", marker: "BEGIN CERTIFICATE"},
		{encoded: "TLS_KEY_PEM_B64", path: "TLS_KEY_FILE", name: "server.key", marker: "BEGIN"},
		{encoded: "CLIENT_CA_PEM_B64", path: "CLIENT_CA_FILE", name: "client-ca.crt", marker: "BEGIN CERTIFICATE"},
	}

	provided := 0
	for _, item := range fields {
		if strings.TrimSpace(os.Getenv(item.encoded)) != "" {
			provided++
		}
	}
	if provided == 0 {
		return nil
	}
	if provided != len(fields) {
		return fmt.Errorf("sealed TLS material must provide TLS_CERT_PEM_B64, TLS_KEY_PEM_B64, and CLIENT_CA_PEM_B64 together")
	}
	for _, item := range fields {
		if strings.TrimSpace(os.Getenv(item.path)) != "" {
			return fmt.Errorf("%s cannot be combined with sealed TLS material", item.path)
		}
	}

	dir := strings.TrimSpace(os.Getenv("TLS_MATERIAL_DIR"))
	if dir == "" {
		dir = "/tmp/meter-tls"
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create sealed TLS directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("protect sealed TLS directory: %w", err)
	}

	for _, item := range fields {
		pem, err := decodePEM(os.Getenv(item.encoded))
		if err != nil {
			return fmt.Errorf("%s: %w", item.encoded, err)
		}
		if !strings.Contains(string(pem), item.marker) {
			return fmt.Errorf("%s is not PEM material of the expected type", item.encoded)
		}
		path := filepath.Join(dir, item.name)
		if err := writePrivateFile(path, pem); err != nil {
			return fmt.Errorf("write %s: %w", item.name, err)
		}
		if err := os.Setenv(item.path, path); err != nil {
			return fmt.Errorf("set %s: %w", item.path, err)
		}
	}
	return nil
}

func decodePEM(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(value)
	}
	if err != nil || len(decoded) == 0 {
		return nil, fmt.Errorf("must be non-empty standard-base64 PEM")
	}
	return decoded, nil
}

func writePrivateFile(path string, contents []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".sealed-tls-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(contents); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempName, path)
}
