.PHONY: gen-bpf gen-compile-commands run-tracer
gen-bpf:
	go generate ./...

gen-compile-commands:
	@bear --force-wrapper -- make gen-bpf

run-tracer: gen-bpf
	go run -exec sudo cmd/cli/main.go tracer
