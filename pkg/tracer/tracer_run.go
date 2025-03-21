package tracer

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
)

type file struct {
	path string
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

		strings, err := t.snapshotStrings()
		if err != nil {
			t.log.Error("error while snapshotting strings", slog.Any("error", err))
		}

		files := resolveFiles(t.log, strings, rawFiles)
		fileAccess := resolveFileAccess(t.log, strings, files, rawFileAccess)

		for k, v := range fileAccess {
			fmt.Println(k, "recorded file access", len(v))
			fmt.Println("====== Cgroup", k)
			for _, f := range v {
				fmt.Println(f.path)
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

func (t *Tracer) snapshotStrings() (map[hash]string, error) {
	result := map[hash]string{}

	iter := t.objs.Strings.Iterate()

	var key tracerStringKey
	var val tracerStringValue

	var collisions uint64

	for iter.Next(&key, &val) {
		result[key.Hash] = unix.ByteSliceToString(val.Str[:])

		if val.CollisionCounter > 0 {
			collisions += uint64(val.CollisionCounter)
		}
	}

	if iter.Err() != nil {
		return nil, iter.Err()
	}

	MapSize.With(prometheus.Labels{"type": "strings"}).Set(float64(len(result)))
	Collisions.With(prometheus.Labels{"type": "strings"}).Set(float64(collisions))

	return result, nil
}

func resolveFileAccess(log *slog.Logger, stringLookup map[hash]string, fileLookup map[hash]file, rawFilesAccess map[tracerFileAccessKey]tracerFileAccessValue) map[cgroupID][]file {
	result := map[cgroupID][]file{}

	for key, _ := range rawFilesAccess {
		file, found := fileLookup[key.FileId]
		if !found {
			log.Warn("file not found", slog.Any("file_id", key.FileId))
			Missing.With(prometheus.Labels{"type": "files"}).Add(1)
			continue
		}

		result[key.CgroupId] = append(result[key.CgroupId], file)
	}

	return result
}

func resolveFiles(log *slog.Logger, stringLookup map[uint32]string, rawFiles map[tracerFileKey]tracerFileValue) map[uint32]file {
	result := map[uint32]file{}

	var fileStringBuf [16]string

	var collisions uint64

outer:
	for key, val := range rawFiles {
		for idx, v := range val.Path.Parts[:] {
			if v == 0 {
				result[key.Hash] = file{
					path: "/" + strings.Join(fileStringBuf[:idx], "/"),
				}
				break
			}

			var str string

			// If the MSB is set, we know that the ID we got needs to be resovled, if it is
			// not set, the ID contains a backed path.
			if v&(1<<31) != 0 {
				s, found := stringLookup[v]
				if !found {
					log.Warn("unknown string", slog.Any("hash", v))
					Missing.With(prometheus.Labels{"type": "strings"}).Add(1)
					// It can happen that we are missing strings, as it is not a atomic operation to
					// load strings and files. It is safe to continue here, as we should get the string
					// in the next iteration.
					continue outer
				}
				str = s
			} else {
				rawBytes := make([]byte, 4)
				data := make([]byte, 0, 4)

				binary.LittleEndian.PutUint32(rawBytes, v)

				for _, c := range rawBytes {
					if c == 0 {
						continue
					}
					data = append(data, c)
				}

				str = string(data)
			}

			fileStringBuf[idx] = str
		}

		if val.CollisionCounter > 0 {
			log.Warn("encountered collision", slog.String("path", result[key.Hash].path))
			collisions += uint64(val.CollisionCounter)
		}
	}

	MapSize.With(prometheus.Labels{"type": "files"}).Set(float64(len(result)))
	Collisions.With(prometheus.Labels{"type": "files"}).Set(float64(collisions))

	return result
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
