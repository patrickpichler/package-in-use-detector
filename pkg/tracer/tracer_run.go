package tracer

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func (t *Tracer) Export(ctx context.Context) error {
	timer := time.NewTicker(10 * time.Second)

	for {
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil
		}

		strings, err := t.snapshotStrings()
		if err != nil {
			t.log.Error("error while snapotting strings", slog.Any("error", err))
		}

		files, err := t.snapshotFiles(strings)

		for _, v := range files {
			fmt.Println(v)
		}
	}
}

func (t *Tracer) snapshotStrings() (map[uint32]string, error) {
	result := map[uint32]string{}

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

func (t *Tracer) snapshotFiles(stringLookup map[uint32]string) (map[uint32]string, error) {
	result := map[uint32]string{}

	iter := t.objs.Files.Iterate()

	var key tracerFileKey
	var val tracerFileValue

	var fileStringBuf [16]string

	for iter.Next(&key, &val) {
		for idx, v := range val.Path.Parts[:] {
			if v == 0 {
				result[key.Hash] = "/" + strings.Join(fileStringBuf[:idx], "/")
				break
			}

			var str string

			if v&(1<<31) != 0 {
				s, found := stringLookup[v]
				if !found {
					t.log.Warn("unknown string", slog.Any("hash", v))
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
			t.log.Warn("encountered collision", slog.String("path", result[key.Hash]))
		}
	}

	if iter.Err() != nil {
		return nil, iter.Err()
	}

	return result, nil
}
