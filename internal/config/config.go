// Package config loads the deliberately narrow mTLS meter-ingress settings.
package config

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Config contains only network-boundary configuration. No model, customer, or
// prompt setting belongs in this process.
type Config struct {
	ListenAddr            string
	TLSCertFile           string
	TLSKeyFile            string
	ClientCAFile          string
	ExpectedClientSPKIs   map[string]struct{}
	BillingMeterURL       string
	BillingIngressSecret  string
	RequestTimeoutSeconds int
}

func FromEnv(getenv func(string) string) (Config, error) {
	cfg := Config{
		ListenAddr:            defaultValue(getenv("LISTEN_ADDR"), ":8443"),
		TLSCertFile:           strings.TrimSpace(getenv("TLS_CERT_FILE")),
		TLSKeyFile:            strings.TrimSpace(getenv("TLS_KEY_FILE")),
		ClientCAFile:          strings.TrimSpace(getenv("CLIENT_CA_FILE")),
		BillingMeterURL:       strings.TrimSpace(getenv("BILLING_METER_URL")),
		BillingIngressSecret:  strings.TrimSpace(getenv("BILLING_INGRESS_SECRET")),
		ExpectedClientSPKIs:   map[string]struct{}{},
		RequestTimeoutSeconds: 15,
	}
	for _, field := range []struct{ name, value string }{
		{"TLS_CERT_FILE", cfg.TLSCertFile},
		{"TLS_KEY_FILE", cfg.TLSKeyFile},
		{"CLIENT_CA_FILE", cfg.ClientCAFile},
		{"BILLING_METER_URL", cfg.BillingMeterURL},
		{"BILLING_INGRESS_SECRET", cfg.BillingIngressSecret},
	} {
		if field.value == "" {
			return Config{}, fmt.Errorf("%s is required", field.name)
		}
	}
	parsed, err := url.Parse(cfg.BillingMeterURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "/cc/meter" {
		return Config{}, fmt.Errorf("BILLING_METER_URL must be an exact https://host/cc/meter URL")
	}
	if value := strings.TrimSpace(getenv("REQUEST_TIMEOUT_SECONDS")); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 60 {
			return Config{}, fmt.Errorf("REQUEST_TIMEOUT_SECONDS must be an integer between 1 and 60")
		}
		cfg.RequestTimeoutSeconds = n
	}
	for _, raw := range strings.Split(getenv("EXPECTED_CLIENT_SPKI_SHA256"), ",") {
		fingerprint := strings.TrimSpace(raw)
		if fingerprint == "" {
			continue
		}
		if _, err := decodeFingerprint(fingerprint); err != nil {
			return Config{}, fmt.Errorf("EXPECTED_CLIENT_SPKI_SHA256: %w", err)
		}
		cfg.ExpectedClientSPKIs[fingerprint] = struct{}{}
	}
	return cfg, nil
}

func Load() (Config, error) { return FromEnv(os.Getenv) }

func defaultValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func decodeFingerprint(value string) ([]byte, error) {
	if !strings.HasPrefix(value, "sha256:") {
		return nil, fmt.Errorf("must start with sha256:")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, "sha256:"))
	if err != nil || len(decoded) != sha256.Size {
		return nil, fmt.Errorf("must be a base64url SHA-256 digest")
	}
	return decoded, nil
}
