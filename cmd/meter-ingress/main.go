package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/AdverserialAI/confidential-meter-ingress/internal/config"
	"github.com/AdverserialAI/confidential-meter-ingress/internal/ingress"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid configuration", "error", err.Error())
		os.Exit(2)
	}
	tlsConfig, err := ingress.TLSConfig(cfg)
	if err != nil {
		logger.Error("invalid TLS configuration", "error", err.Error())
		os.Exit(2)
	}
	server, err := ingress.New(cfg, logger)
	if err != nil {
		logger.Error("cannot start ingress", "error", err.Error())
		os.Exit(2)
	}
	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           server.Handler(),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5e9,
		ReadTimeout:       20e9,
		WriteTimeout:      20e9,
		IdleTimeout:       60e9,
		MaxHeaderBytes:    8 << 10,
	}
	logger.Info("meter ingress listening", "address", cfg.ListenAddr)
	if err := httpServer.ListenAndServeTLS("", ""); err != nil {
		logger.Error("meter ingress stopped", "error", err.Error())
		os.Exit(1)
	}
}
