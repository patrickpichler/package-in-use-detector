package tracer

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 tracer ./c/tracer.bpf.c -- -I../../c/headers -Wno-address-of-packed-member -O2 -fno-stack-protector
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 tracer ./c/tracer.bpf.c -- -I../../c/headers -Wno-address-of-packed-member -O2 -fno-stack-protector -g
