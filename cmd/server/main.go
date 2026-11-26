package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/bayonos/backend-go/internal/auth"
	"github.com/bayonos/backend-go/internal/config"
	"github.com/bayonos/backend-go/internal/server"
	"github.com/bayonos/backend-go/internal/store"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("Fatal error: %v", err)
	}
}

func run() error {
	ctx := context.Background()
	cfg := config.LoadConfig(config.Environ(), ".env")
	if cfg.JWTSecretIsEphemeral {
		log.Print("[WARN] JWT_SECRET is not set; generated an ephemeral secret for this process.")
	}

	db, err := store.New(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := db.InitSchema(ctx); err != nil {
		return err
	}

	authService := auth.NewService(db, cfg)
	httpServer := &http.Server{
		Addr:              cfg.Host + ":" + strconv.Itoa(cfg.Port),
		Handler:           server.NewHandler(authService),
		ReadHeaderTimeout: 10 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		log.Printf("Auth server listening on http://%s:%d (db=%s, runtime=go)", cfg.Host, cfg.Port, dbDescription(cfg))
		serverErr <- httpServer.ListenAndServe()
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-signals:
		log.Printf("Shutting down on %s", sig)
	case err := <-serverErr:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return httpServer.Shutdown(shutdownCtx)
}

func dbDescription(cfg config.Config) string {
	if cfg.DBDriver == "sqlite" {
		return "sqlite:" + cfg.DBPath
	}
	return "mysql://" + cfg.MySQLUser + "@" + cfg.MySQLHost + ":" + strconv.Itoa(cfg.MySQLPort) + "/" + cfg.MySQLDatabase
}
