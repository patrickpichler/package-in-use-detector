package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"gitlab.com/castai/package-in-use-detector/cmd/cli/commands"
)

func main() {
	rootCmd := &cobra.Command{
		Use: "package-in-use-detector",
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	rootCmd.AddCommand(
		commands.TracerCommand(log),
		commands.DebugCommand(log),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("error while execution: %v", err)
		os.Exit(1)
	}
}
