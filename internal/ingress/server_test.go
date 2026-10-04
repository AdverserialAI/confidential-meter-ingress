package ingress

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AdverserialAI/confidential-meter-ingress/internal/config"
)

type testPKI struct {
	serverCert string
	serverKey  string
	clientCA   string
	client     tls.Certificate
	roots      *x509.CertPool
	clientPin  string
}

func writePEM(t *testing.T, name string, blocks ...*pem.Block) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	for _, block := range blocks {
		if err := pem.Encode(f, block); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func signedCert(t *testing.T, template, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "meter-client-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "meter.example"}, DNSNames: []string{"meter.example"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, serverKey := signedCert(t, serverTemplate, caCert, caKey)
	clientTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "cvm-meter-client"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	clientDER, clientKey := signedCert(t, clientTemplate, caCert, caKey)
	serverCert := writePEM(t, "server.crt", &pem.Block{Type: "CERTIFICATE", Bytes: serverDER}, &pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	serverKeyPath := writePEM(t, "server.key", &pem.Block{Type: "EC PRIVATE KEY", Bytes: mustMarshalEC(t, serverKey)})
	clientCA := writePEM(t, "client-ca.crt", &pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	client, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: mustMarshalEC(t, clientKey)}))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	clientLeaf, err := x509.ParseCertificate(clientDER)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(clientLeaf.RawSubjectPublicKeyInfo)
	return testPKI{serverCert: serverCert, serverKey: serverKeyPath, clientCA: clientCA, client: client, roots: roots, clientPin: "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:])}
}

func mustMarshalEC(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func testConfig(pki testPKI, billingURL string) config.Config {
	return config.Config{ListenAddr: "127.0.0.1:0", TLSCertFile: pki.serverCert, TLSKeyFile: pki.serverKey, ClientCAFile: pki.clientCA, ExpectedClientSPKIs: map[string]struct{}{pki.clientPin: {}}, BillingMeterURL: billingURL, BillingIngressSecret: "ingress-secret", RequestTimeoutSeconds: 5}
}

func testIngress(t *testing.T, pki testPKI, billingURL string) (*httptest.Server, *Server) {
	t.Helper()
	cfg := testConfig(pki, billingURL)
	s, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := TLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.TLS = tlsCfg
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts, s
}

func meterBody() []byte { return []byte(`{"meter":"a.b.c"}`) }

func mTLSClient(pki testPKI) *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pki.roots, Certificates: []tls.Certificate{pki.client}, MinVersion: tls.VersionTLS13}}}
}

func TestMeterRequiresMTLSAndForwardsBoundedEnvelope(t *testing.T) {
	pki := newTestPKI(t)
	var gotHeader, gotBody string
	billing := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cc/meter" {
			t.Errorf("path = %s", r.URL.Path)
		}
		gotHeader = r.Header.Get("X-Adverserial-Meter-Ingress")
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		gotBody = buf.String()
		w.WriteHeader(http.StatusNoContent)
	}))
	billing.StartTLS()
	t.Cleanup(billing.Close)
	ts, s := testIngress(t, pki, billing.URL+"/cc/meter")
	s.client = billing.Client()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/cc/meter", bytes.NewReader(meterBody()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if _, err := http.DefaultClient.Do(req); err == nil {
		t.Fatal("non-mTLS request unexpectedly succeeded")
	}

	req, err = http.NewRequest(http.MethodPost, ts.URL+"/cc/meter", bytes.NewReader(meterBody()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := mTLSClient(pki).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if gotHeader != "ingress-secret" || gotBody != string(meterBody()) {
		t.Fatalf("billing receive header=%q body=%q", gotHeader, gotBody)
	}
}

func TestRejectsUnpinnedOrMalformedMeter(t *testing.T) {
	pki := newTestPKI(t)
	billing := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(billing.Close)
	ts, s := testIngress(t, pki, billing.URL+"/cc/meter")
	s.client = billing.Client()
	s.cfg.ExpectedClientSPKIs = map[string]struct{}{"sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA": {}}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/cc/meter", bytes.NewReader(meterBody()))
	req.Header.Set("Content-Type", "application/json")
	resp, err := mTLSClient(pki).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unmatched pin status = %d", resp.StatusCode)
	}

	s.cfg.ExpectedClientSPKIs = map[string]struct{}{pki.clientPin: {}}
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/cc/meter", bytes.NewBufferString(`{"meter":"bad"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err = mTLSClient(pki).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed meter status = %d", resp.StatusCode)
	}
}
