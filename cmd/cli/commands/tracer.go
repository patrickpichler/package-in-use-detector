package commands

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"gitlab.com/castai/package-in-use-detector/pkg/tracer"
	"golang.org/x/sync/errgroup"
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
	defer tracer.Close()

	fmt.Println("init...")
	if err := tracer.Init(); err != nil {
		return fmt.Errorf("error while initializing tracer: %w", err)
	}
	fmt.Println("init done...")

	grp, ctx := errgroup.WithContext(ctx)

	grp.Go(func() error {
		return tracer.Export(ctx)
	})

	// TODO(patrick.pichler): move this to a CLI arg or some sort of setting.

	// for _, path := range []string{
	// 	"/proc",
	// 	"/home/patrickp.linux",
	// 	"/sys/fs/cgroup/kubelet.slice",
	// 	"/var/lib/containerd",
	// 	"/cgroups/kubelet.slice",
	// 	"/usr/lib",
	// 	"/etc",
	// 	"/dev",
	// } {
	// 	if err := tracer.IgnorePath(path); err != nil {
	// 		return fmt.Errorf("error while ignoring path %s: %w", path, err)
	// 	}
	// }

	fmt.Println("attach...")
	if err := tracer.Attach(); err != nil {
		return fmt.Errorf("error while attaching tracer: %w", err)
	}
	fmt.Println("attach done...")

	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":8080", nil)

	select {
	case <-ctx.Done():
		log.Info("ctx done... shutdown")
	}

	return nil
}
