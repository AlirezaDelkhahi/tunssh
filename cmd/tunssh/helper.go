package main

import (
	"log/slog"
	"os"
	"slices"

	"github.com/AlirezaDelkhahi/tunssh/internal/app"
)

func shouldRunHelper(args []string) bool {
	return slices.Contains(args, "--tun-helper")
}

func runHelper(args []string) error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	return app.RunHelperMode(args, logger)
}
