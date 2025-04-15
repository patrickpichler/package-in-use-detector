// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"encoding/binary"
	"fmt"
)

func jenkinsOneAtATime(key []byte) uint32 {
	var hash uint32
	for _, b := range key {
		hash += uint32(b)
		hash += (hash << 10)
		hash ^= (hash >> 6)
	}
	hash += (hash << 3)
	hash ^= (hash >> 11)
	hash += (hash << 15)
	return hash
}

// The inline ID mask is always stored in BE. This converts it to whatever the host
// byte order is, so that it can be easily used.
var inlineIdMask = binary.NativeEndian.Uint32([]byte{1 << 7, 0x00, 0x00, 0x00})

func doJHash(str string) uint32 {
	return jenkinsOneAtATime([]byte(str))
}

func ToHashedId(str string) uint32 {
	if len(str) > 4 {
		h := doJHash(str)

		fmt.Printf("h: %v\n", h)

		return h | inlineIdMask
	}

	raw := make([]byte, 4, 4)
	copy(raw, []byte(str))

	return binary.NativeEndian.Uint32(raw)
}
