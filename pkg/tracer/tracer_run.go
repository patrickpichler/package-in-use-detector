package tracer

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type file struct {
	path string
}

type processKey struct {
	pid       uint32
	startTime uint64
}

type mountNsId = uint32

type hash = uint32

func (t *Tracer) Export(ctx context.Context) error {
	timer := time.NewTicker(10 * time.Second)

	for {
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil
		}

		rawFileAccess, err := snapshotMap[tracerFileAccessKey, tracerFileAccessValue](t.objs.tracerMaps.FileAccess)
		if err != nil {
			return err
		}

		rawFiles, err := snapshotMap[tracerFileKey, tracerFileValue](t.objs.tracerMaps.Files)
		if err != nil {
			return err
		}

		strings, err := t.snapshotStrings()
		if err != nil {
			t.log.Error("error while snapotting strings", slog.Any("error", err))
		}

		files := resolveFiles(t.log, strings, rawFiles)
		fileAccess := resolveFileAccess(t.log, strings, files, rawFileAccess)

		for k, v := range fileAccess {
			fmt.Println(k, "recorded file access", len(v))
			for pk, v2 := range v {
				fmt.Println("====== Process", pk.pid, pk.startTime)
				for _, f := range v2 {
					fmt.Println(f.path)
				}
			}
		}
	}
}

func (t *Tracer) snapshotStrings() (map[hash]string, error) {
	result := map[hash]string{}

	iter := t.objs.Strings.Iterate()

	var key tracerStringKey
	var val tracerStringValue

	for iter.Next(&key, &val) {
		result[key.Hash] = unix.ByteSliceToString(val.Str[:])
	}

	if iter.Err() != nil {
		return nil, iter.Err()
	}

	return result, nil
}

func resolveFileAccess(log *slog.Logger, stringLookup map[hash]string, fileLookup map[hash]file, rawFilesAccess map[tracerFileAccessKey]tracerFileAccessValue) map[mountNsId]map[processKey][]file {
	result := map[mountNsId]map[processKey][]file{}

	for key, _ := range rawFilesAccess {
		mntNsMap, found := result[key.MntNs]
		if !found {
			mntNsMap = map[processKey][]file{}
			result[key.MntNs] = mntNsMap
		}

		file, found := fileLookup[key.FileId]
		if !found {
			log.Warn("file not found", slog.Any("file_id", key.FileId))
			continue
		}

		pKey := processKey{
			pid:       uint32(key.Pid),
			startTime: key.ProcessStartTime,
		}
		mntNsMap[pKey] = append(mntNsMap[pKey], file)
	}

	return result
}

func resolveFiles(log *slog.Logger, stringLookup map[uint32]string, rawFiles map[tracerFileKey]tracerFileValue) map[uint32]file {
	result := map[uint32]file{}

	var fileStringBuf [16]string

	for key, val := range rawFiles {
		for idx, v := range val.Path.Parts[:] {
			if v == 0 {
				result[key.Hash] = file{
					path: "/" + strings.Join(fileStringBuf[:idx], "/"),
				}
				break
			}

			var str string

			if v&(1<<31) != 0 {
				s, found := stringLookup[v]
				if !found {
					log.Warn("unknown string", slog.Any("hash", v))
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
		}
	}

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
