// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type tracerConfig struct {
	CurrentStringId  uint64
	MaxStringReached uint64
	CurrentFileId    uint64
	MaxFileReached   uint64
}

type tracerFileAccessKey struct {
	MntNs            uint32
	Pid              int32
	ProcessStartTime uint64
	FileId           uint32
	_                [4]byte
}

type tracerFileAccessValue struct{ Counter uint8 }

type tracerFileKey struct{ Path struct{ Parts [16]uint32 } }

type tracerFileValue struct{ Id uint32 }

type tracerStringKey struct{ Str [255]int8 }

type tracerStringValue struct{ Id uint32 }

// loadTracer returns the embedded CollectionSpec for tracer.
func loadTracer() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_TracerBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load tracer: %w", err)
	}

	return spec, err
}

// loadTracerObjects loads tracer and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*tracerObjects
//	*tracerPrograms
//	*tracerMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadTracerObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadTracer()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// tracerSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tracerSpecs struct {
	tracerProgramSpecs
	tracerMapSpecs
	tracerVariableSpecs
}

// tracerProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tracerProgramSpecs struct {
	SecurityFileOpen *ebpf.ProgramSpec `ebpf:"security_file_open"`
}

// tracerMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tracerMapSpecs struct {
	ConfigMap        *ebpf.MapSpec `ebpf:"config_map"`
	FileAccess       *ebpf.MapSpec `ebpf:"file_access"`
	FilePathScratch  *ebpf.MapSpec `ebpf:"file_path_scratch"`
	Files            *ebpf.MapSpec `ebpf:"files"`
	StringKeyScratch *ebpf.MapSpec `ebpf:"string_key_scratch"`
	Strings          *ebpf.MapSpec `ebpf:"strings"`
}

// tracerVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tracerVariableSpecs struct {
}

// tracerObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadTracerObjects or ebpf.CollectionSpec.LoadAndAssign.
type tracerObjects struct {
	tracerPrograms
	tracerMaps
	tracerVariables
}

func (o *tracerObjects) Close() error {
	return _TracerClose(
		&o.tracerPrograms,
		&o.tracerMaps,
	)
}

// tracerMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadTracerObjects or ebpf.CollectionSpec.LoadAndAssign.
type tracerMaps struct {
	ConfigMap        *ebpf.Map `ebpf:"config_map"`
	FileAccess       *ebpf.Map `ebpf:"file_access"`
	FilePathScratch  *ebpf.Map `ebpf:"file_path_scratch"`
	Files            *ebpf.Map `ebpf:"files"`
	StringKeyScratch *ebpf.Map `ebpf:"string_key_scratch"`
	Strings          *ebpf.Map `ebpf:"strings"`
}

func (m *tracerMaps) Close() error {
	return _TracerClose(
		m.ConfigMap,
		m.FileAccess,
		m.FilePathScratch,
		m.Files,
		m.StringKeyScratch,
		m.Strings,
	)
}

// tracerVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to loadTracerObjects or ebpf.CollectionSpec.LoadAndAssign.
type tracerVariables struct {
}

// tracerPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadTracerObjects or ebpf.CollectionSpec.LoadAndAssign.
type tracerPrograms struct {
	SecurityFileOpen *ebpf.Program `ebpf:"security_file_open"`
}

func (p *tracerPrograms) Close() error {
	return _TracerClose(
		p.SecurityFileOpen,
	)
}

func _TracerClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed tracer_arm64_bpfel.o
var _TracerBytes []byte
