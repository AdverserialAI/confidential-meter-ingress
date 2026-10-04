package config

import (
	"strings"
	"testing"
)

func env(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func validEnv() map[string]string {
	return map[string]string{
		"TLS_CERT_FILE": "server.crt", "TLS_KEY_FILE": "server.key", "CLIENT_CA_FILE": "client-ca.crt",
		"BILLING_METER_URL": "https://billing.example/cc/meter", "BILLING_INGRESS_SECRET": "secret",
	}
}

func TestRequiresBoundarySettings(t *testing.T) {
	for _, missing := range []string{"TLS_CERT_FILE", "TLS_KEY_FILE", "CLIENT_CA_FILE", "BILLING_METER_URL", "BILLING_INGRESS_SECRET"} {
		values := validEnv()
		delete(values, missing)
		if _, err := FromEnv(env(values)); err == nil || !strings.Contains(err.Error(), missing) {
			t.Fatalf("missing %s: got %v", missing, err)
		}
	}
}

func TestRejectsUnsafeBillingURL(t *testing.T) {
	for _, endpoint := range []string{
		"http://billing.example/cc/meter", "https://billing.example/other", "https://user@billing.example/cc/meter",
		"https://billing.example/cc/meter?x=1", "https:///cc/meter",
	} {
		values := validEnv()
		values["BILLING_METER_URL"] = endpoint
		if _, err := FromEnv(env(values)); err == nil {
			t.Fatalf("unsafe endpoint accepted: %s", endpoint)
		}
	}
}

func TestValidPinAndTimeout(t *testing.T) {
	values := validEnv()
	values["EXPECTED_CLIENT_SPKI_SHA256"] = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	values["REQUEST_TIMEOUT_SECONDS"] = "60"
	cfg, err := FromEnv(env(values))
	if err != nil || len(cfg.ExpectedClientSPKIs) != 1 || cfg.RequestTimeoutSeconds != 60 {
		t.Fatalf("valid config = %#v, %v", cfg, err)
	}
}
