package commands

import (
	"context"
	"fmt"
	"log/slog"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"gitlab.com/castai/package-in-use-detector/pkg/tracer"
)

func TracerCommand(log *slog.Logger) *cobra.Command {
	return &cobra.Command{
		Use: "tracer",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			ctx, cancel := signal.NotifyContext(ctx, syscall.SIGTERM)
			defer cancel()

			return runTracer(ctx, log)
		},
	}
}

func runTracer(ctx context.Context, log *slog.Logger) error {
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
