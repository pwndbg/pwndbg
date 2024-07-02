.PHONY: all
all: reference-binary.aarch64.out reference-binary.riscv64.out

%.aarch64.out : %.aarch64.c
	@echo "[+] Building '$@'"
	@aarch64-linux-gnu-gcc $(CFLAGS) $(EXTRA_FLAGS) -w -o $@ $< $(LDFLAGS)

# apt install crossbuild-essential-riscv64
%.riscv64.out : %.riscv64.c
	@echo "[+] Building '$@'"
	@riscv64-linux-gnu-gcc -march=rv64gc -mabi=lp64d -g $(CFLAGS) $(EXTRA_FLAGS) -w -o $@ $? $(LDFLAGS)

AARCH64_SOURCES := $(wildcard *.aarch64.c)
AARCH64_TARGETS := $(AARCH64_SOURCES:.aarch64.c=.aarch64.out)

RISCV64_SOURCES := $(wildcard *.riscv64.c)
RISCV64_TARGETS := $(RISCV64_SOURCES:.riscv64.c=.riscv64.out)

clean:
	rm -f *.aarch64.out *.x86_64.out *.arm.out
