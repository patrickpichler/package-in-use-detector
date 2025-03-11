package tracer

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

var (
	ErrTracerNotInitialized     = errors.New("tracer not initialized")
	ErrTracerAlreadyInitialized = errors.New("tracer already initialized")
)

type tracerEBPFLinks struct {
	securityFileOpenLink link.Link
}

type Tracer struct {
	log          *slog.Logger
	programLinks *tracerEBPFLinks
	objs         *tracerObjects
	initialized  atomic.Bool
	initMu       sync.Mutex
}

func New(log *slog.Logger) (*Tracer, error) {
	return &Tracer{
		log: log,
	}, nil
}

func (t *Tracer) load() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("error while removing memlock: %w", err)
	}

	spec, err := loadTracer()
	if err != nil {
		return fmt.Errorf("error loading tracer bpf spec: %w", err)
	}

	var objs tracerObjects

	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.log.Error(fmt.Sprintf("Verifier error: %+v", ve))
		}

		return fmt.Errorf("error while loading and assigning tracer objs: %w", err)
	}

	t.objs = &objs

	return nil
}

func (t *Tracer) attach() error {
	securityFileOpenLink, err := link.Kprobe("security_file_open", t.objs.SecurityFileOpen, nil)
	if err != nil {
		return fmt.Errorf("error while attaching security_file_open link: %w", err)
	}

	t.programLinks = &tracerEBPFLinks{
		securityFileOpenLink: securityFileOpenLink,
	}

	return nil
}

func (t *Tracer) Init() error {
	t.initMu.Lock()
	defer t.initMu.Unlock()

	if t.initialized.Load() {
		return ErrTracerAlreadyInitialized
	}

	if err := t.load(); err != nil {
		return fmt.Errorf("error during load: %w", err)
	}

	if err := t.attach(); err != nil {
		return fmt.Errorf("error during attaching: %w", err)
	}

	return nil
}

func (t *Tracer) Close() {
	if t.programLinks != nil {
		t.programLinks.securityFileOpenLink.Close()
	}
}
