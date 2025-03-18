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

type tracerEBPFMapSpec struct {
	fileAccessSpec *ebpf.MapSpec
}

type Tracer struct {
	log          *slog.Logger
	programLinks *tracerEBPFLinks
	objs         *tracerObjects
	mapSpecs     tracerEBPFMapSpec
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

	mapBufferSpec, found := spec.Maps["file_access_buffer_map"]
	if !found {
		return fmt.Errorf("error file_access_buffer_map spec not found")
	}

	t.mapSpecs.fileAccessSpec = mapBufferSpec
	fileAccessBuffer, err := buildFileAccessBufferMap(mapBufferSpec)
	if err != nil {
		return fmt.Errorf("error while building file access map buffer: %w", err)
	}

	var objs tracerObjects

	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"file_access_buffer_map": fileAccessBuffer,
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.log.Error(fmt.Sprintf("Verifier error: %+v", ve))
		}

		return fmt.Errorf("error while loading and assigning tracer objs: %w", err)
	}

	t.objs = &objs

	return nil
}

func buildFileAccessBufferMap(origSpec *ebpf.MapSpec) (*ebpf.Map, error) {
	spec := origSpec.Copy()
	spec.Contents = make([]ebpf.MapKV, spec.MaxEntries)

	for i := uint32(0); i < spec.MaxEntries; i++ {
		innerSpec := spec.InnerMap.Copy()
		innerSpec.Name = fmt.Sprintf("file_acc_%d", i)

		innerMap, err := ebpf.NewMap(innerSpec)
		if err != nil {
			return nil, err
		}
		defer innerMap.Close()

		spec.Contents[i] = ebpf.MapKV{Key: i, Value: innerMap}
	}

	outerMap, err := ebpf.NewMap(spec)
	if err != nil {
		return nil, err
	}

	return outerMap, nil
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

	return nil
}

func (t *Tracer) Attach() error {
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
