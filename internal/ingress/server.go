// Package ingress implements a fixed-purpose mTLS ingress for meter events.
package ingress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/AdverserialAI/confidential-meter-ingress/internal/config"
)

const maxMeterBodyBytes = 16 * 1024

// Server has no persistence and holds no meter signing key. It merely proves
// network possession of the dedicated client certificate, then forwards the
// sealed count-only JWS to its fixed billing endpoint.
type Server struct {
	cfg        config.Config
	client     *http.Client
	billingURL string
	logger     *slog.Logger
}

func New(cfg config.Config, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	parsed, err := url.Parse(cfg.BillingMeterURL)
	if err != nil {
		return nil, fmt.Errorf("parse billing URL: %w", err)
	}
	return &Server{
		cfg:        cfg,
		billingURL: parsed.String(),
		logger:     logger,
		client:     &http.Client{Timeout: time.Duration(cfg.RequestTimeoutSeconds) * time.Second},
	}, nil
}

// TLSConfig requires a client certificate which chains to the dedicated meter
// CA. The optional SPKI pin is enforced at request time after the handshake.
func TLSConfig(cfg config.Config) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read client CA: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("CLIENT_CA_FILE has no PEM certificate")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"http/1.1"},
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("POST /cc/meter", s.handleMeter)
	return securityHeaders(mux)
}

func (s *Server) handleMeter(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	if !s.pinnedClient(r.TLS.PeerCertificates[0]) {
		http.Error(w, "unrecognized meter client certificate", http.StatusForbidden)
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxMeterBodyBytes))
	if err != nil {
		http.Error(w, "meter body is too large", http.StatusRequestEntityTooLarge)
		return
	}
	if !validMeterEnvelope(body) {
		http.Error(w, "invalid meter envelope", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.cfg.RequestTimeoutSeconds)*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.billingURL, bytes.NewReader(body))
	if err != nil {
		s.logger.Error("create billing meter request failed", "error", err.Error())
		http.Error(w, "billing unavailable", http.StatusBadGateway)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Adverserial-Meter-Ingress", s.cfg.BillingIngressSecret)
	resp, err := s.client.Do(req)
	if err != nil {
		s.logger.Warn("billing meter request failed", "error", err.Error())
		http.Error(w, "billing unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	// Drain a bounded body to keep the transport reusable. Do not expose billing
	// response details, which might reveal account or ledger state to the CVM.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		s.logger.Warn("billing rejected meter", "status", resp.StatusCode)
		http.Error(w, "billing rejected meter", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) pinnedClient(cert *x509.Certificate) bool {
	if len(s.cfg.ExpectedClientSPKIs) == 0 {
		return true
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	fingerprint := "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:])
	_, ok := s.cfg.ExpectedClientSPKIs[fingerprint]
	return ok
}

func validMeterEnvelope(body []byte) bool {
	var payload struct {
		Meter any `json:"meter"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&payload) != nil {
		return false
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return false
	}
	token, ok := payload.Meter.(string)
	// Compact JWS must be bounded. Signature semantics remain billing's job.
	return ok && len(token) > 0 && len(token) <= 16_384 && strings.Count(token, ".") == 2
}

func isJSONContentType(value string) bool {
	return strings.EqualFold(strings.TrimSpace(strings.Split(value, ";")[0]), "application/json")
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		next.ServeHTTP(w, r)
	})
}
