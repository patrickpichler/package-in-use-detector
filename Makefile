.PHONY: gen-bpf gen-compile-commands run-tracer

pkg/tracer/%.o: pkg/tracer/c/tracer.bpf.c $(wildcard c/headers/*.h)
	go generate ./pkg/tracer/ebpf.go

gen-bpf: $(wildcard pkg/tracer/*.o)

gen-compile-commands:
	@bear --force-wrapper -- make gen-bpf

run-tracer: gen-bpf
	go run -exec sudo cmd/cli/main.go tracer
