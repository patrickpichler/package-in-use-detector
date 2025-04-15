package tracer

// #cgo CFLAGS: -g -I ../../c/headers/ -D __GOLANG_TEST
// #include <stdlib.h>
// #include "jhash.h"
import "C"
import (
	"unsafe"
)

func jenkinsOneAtATimeC(data []byte) uint32 {
	if len(data) > 255 {
		panic("data too long")
	}

	ptr := unsafe.Pointer(&data[0])

	res := C.jenkins_one_at_a_time(ptr, C.__u32(len(data)))

	return uint32(res)
}
