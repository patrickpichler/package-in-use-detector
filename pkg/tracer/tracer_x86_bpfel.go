// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type tracerConfig struct{ CurrentFileAccessIdx uint32 }

type tracerFileAccessKey struct {
	MntNs            uint32
	Pid              int32
	ProcessStartTime uint64
	FileId           uint32
	_                [4]byte
}

type tracerFileAccessValue struct{ Counter uint8 }

type tracerFileKey struct{ Hash uint32 }

type tracerFileValue struct {
	Path             struct{ Parts [16]uint32 }
	CollisionCounter uint32
}

type tracerStringKey struct{ Hash uint32 }

type tracerStringValue struct {
	Str              [252]uint8
	CollisionCounter uint32
}

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
	ConfigMap           *ebpf.MapSpec `ebpf:"config_map"`
	FileAccessBufferMap *ebpf.MapSpec `ebpf:"file_access_buffer_map"`
	FilePathScratch     *ebpf.MapSpec `ebpf:"file_path_scratch"`
	FileValueScratch    *ebpf.MapSpec `ebpf:"file_value_scratch"`
	Files               *ebpf.MapSpec `ebpf:"files"`
	StringValueScratch  *ebpf.MapSpec `ebpf:"string_value_scratch"`
	Strings             *ebpf.MapSpec `ebpf:"strings"`
}

// tracerVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tracerVariableSpecs struct {
	UnusdFileAccessKey *ebpf.VariableSpec `ebpf:"unusd_file_access_key"`
	UnusdFileAccessVal *ebpf.VariableSpec `ebpf:"unusd_file_access_val"`
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
	ConfigMap           *ebpf.Map `ebpf:"config_map"`
	FileAccessBufferMap *ebpf.Map `ebpf:"file_access_buffer_map"`
	FilePathScratch     *ebpf.Map `ebpf:"file_path_scratch"`
	FileValueScratch    *ebpf.Map `ebpf:"file_value_scratch"`
	Files               *ebpf.Map `ebpf:"files"`
	StringValueScratch  *ebpf.Map `ebpf:"string_value_scratch"`
	Strings             *ebpf.Map `ebpf:"strings"`
}

func (m *tracerMaps) Close() error {
	return _TracerClose(
		m.ConfigMap,
		m.FileAccessBufferMap,
		m.FilePathScratch,
		m.FileValueScratch,
		m.Files,
		m.StringValueScratch,
		m.Strings,
	)
}

// tracerVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to loadTracerObjects or ebpf.CollectionSpec.LoadAndAssign.
type tracerVariables struct {
	UnusdFileAccessKey *ebpf.Variable `ebpf:"unusd_file_access_key"`
	UnusdFileAccessVal *ebpf.Variable `ebpf:"unusd_file_access_val"`
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
//go:embed tracer_x86_bpfel.o
var _TracerBytes []byte
