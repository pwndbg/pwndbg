.PHONY: all
all: reference-binary.aarch64.out reference-binary.riscv64.out

reference-binary.aarch64.out : reference-binary.aarch64.c
	@echo "[+] Building '$@'"
	@aarch64-linux-gnu-gcc $(CFLAGS) $(EXTRA_FLAGS) -w -o $@ $? $(LDFLAGS)

# apt install crossbuild-essential-riscv64
reference-binary.riscv64.out : reference-binary.riscv64.c
	@echo "[+] Building '$@'"
	@riscv64-linux-gnu-gcc -march=rv64gc -mabi=lp64d -g $(CFLAGS) $(EXTRA_FLAGS) -w -o $@ $? $(LDFLAGS)

clean:
	rm reference-binary.aarch64.out
	rm reference-binary.riscv64.out