.DEFAULT_GOAL := build

vmlinux.h:
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

bpf_cubic.o: bpf_cubic.c vmlinux.h
	clang-14 -target bpf -I/usr/include/$(uname -m)-linux-gnu -g -O2 -o bpf_cubic.o -c bpf_cubic.c

build: bpf_cubic.o

clean:
	rm -f bpf_cubic.o vmlinux.h

.PHONY: build clean
