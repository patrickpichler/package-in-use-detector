package tracer

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type file struct {
	path    string
	rawPath tracerFilePath
	ignored bool
}

type processKey struct {
	pid       uint32
	startTime uint64
}

type cgroupID = uint64

type hash = uint32

func (t *Tracer) Export(ctx context.Context) error {
	timer := time.NewTicker(10 * time.Second)

	for {
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil
		}

		rawFileAccess, err := t.collectFileAccess()
		if err != nil {
			return err
		}

		rawFiles, err := snapshotMap[tracerFileKey, tracerFileValue](t.objs.tracerMaps.Files)
		if err != nil {
			return err
		}

		fileAccess := map[uint64][]file{}

		for k, _ := range rawFileAccess {
			f, found := rawFiles[tracerFileKey{Hash: k.FileId}]
			if !found {
				t.log.Warn("missing file cgroupId: %s, fileId: %d", k.CgroupId, k.FileId)
				continue
			}

			fileAccess[k.CgroupId] = append(fileAccess[k.CgroupId], file{
				path:    unix.ByteSliceToString(f.Path.Path[:]),
				ignored: false,
			})
		}

		for k, v := range fileAccess {
			fmt.Println(k, "recorded file access", len(v))
			fmt.Println("====== Cgroup", k)
			for _, f := range v {
				fmt.Println(f.ignored, f.path)
			}
		}
	}
}

func (t *Tracer) collectFileAccess() (map[tracerFileAccessKey]tracerFileAccessValue, error) {
	var config tracerConfig

	zero := uint32(0)

	err := t.objs.ConfigMap.Lookup(zero, &config)
	if err != nil {
		return nil, fmt.Errorf("error while config lookup: %w", err)
	}

	numEntries := t.objs.FileAccessBufferMap.MaxEntries()
	indexToCollect := config.CurrentFileAccessIdx

	config.CurrentFileAccessIdx = (config.CurrentFileAccessIdx + 1) % numEntries

	err = t.objs.ConfigMap.Update(zero, &config, ebpf.UpdateExist)
	if err != nil {
		return nil, fmt.Errorf("error while updating config: %w", err)
	}

	innerMapSpec := t.mapSpecs.fileAccessSpec.InnerMap.Copy()
	if innerMapSpec == nil {
		return nil, errors.New("error: no inner map spec for `fileAccess`")
	}
	innerMapSpec.Name = fmt.Sprintf("file_acc_%d", indexToCollect)

	newMap, err := ebpf.NewMap(innerMapSpec)
	if err != nil {
		return nil, fmt.Errorf("error while creating new inner map: %w", err)
	}
	defer newMap.Close()

	var fileAccessMap *ebpf.Map
	err = t.objs.FileAccessBufferMap.Lookup(indexToCollect, &fileAccessMap)
	if err != nil {
		return nil, fmt.Errorf("error while getting existing map: %w", err)
	}
	defer fileAccessMap.Close()

	err = t.objs.FileAccessBufferMap.Update(indexToCollect, newMap, ebpf.UpdateAny)
	if err != nil {
		return nil, fmt.Errorf("error while replacing existing map: %w", err)
	}

	return snapshotMap[tracerFileAccessKey, tracerFileAccessValue](fileAccessMap)
}

func snapshotMap[K comparable, V any](m *ebpf.Map) (map[K]V, error) {
	result := map[K]V{}

	iter := m.Iterate()

	var key K
	var val V

	for iter.Next(&key, &val) {
		result[key] = val
	}

	if iter.Err() != nil {
		return nil, iter.Err()
	}

	return result, nil
}
