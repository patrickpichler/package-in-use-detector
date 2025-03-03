package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"gitlab.com/castai/package-in-use-detector/pkg/tracer"
)

func main() {
	ctx := context.Background()
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGTERM)
	defer cancel()

	log := slog.Default()

	if err := run(log, ctx); err != nil {
		println(err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger, ctx context.Context) error {
	tracer, err := tracer.New(log)
	if err != nil {
		return fmt.Errorf("error while loading tracer: %w", err)
	}

	fmt.Println("init...")
	if err := tracer.Init(); err != nil {
		return fmt.Errorf("error while initializing tracer: %w", err)
	}
	fmt.Println("init done...")

	select {
	case <-ctx.Done():
		log.Info("ctx done... shutdown")
	}

	return nil
}
