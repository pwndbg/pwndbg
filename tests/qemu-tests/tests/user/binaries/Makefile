.PHONY: all

ARCHS = aarch64 arm riscv64 mips64 mips32

CC.aarch64 = aarch64-linux-gnu-gcc
CC.arm = arm-linux-gnueabihf-gcc
CC.riscv64 = riscv64-linux-gnu-gcc
# Ubuntu riscv64 cross compiler package doesn't have "--enable-multilib" enabled to allow compiling to 32-bit
# CC.riscv32 = riscv64-linux-gnu-gcc
CC.mips64 = mips64-linux-gnuabi64-gcc
CC.mips32 = mips-linux-gnu-gcc
# CC.loongarch64 = loongarch64-linux-gnu-gcc-14

ALL_FLAGS = -g

CFLAGS.aarch64 = $(ALL_FLAGS)
CFLAGS.arm = $(ALL_FLAGS)
CFLAGS.riscv64 = -march=rv64gc -mabi=lp64d $(ALL_FLAGS)
# CFLAGS.riscv32 = -march=rv32gc $(ALL_FLAGS)
CFLAGS.mips64 = $(ALL_FLAGS)
CFLAGS.mips32 = $(ALL_FLAGS)
# CFLAGS.loongarch64 = $(ALL_FLAGS)

# Build basic.c for all architectures
BASIC_C_TARGETS = $(ARCHS:%=basic.%.out)
basic.%.out: basic.c
	echo $@ "hello" $<
	$(CC.$*) $(CFLAGS.$*) -o $@ $<


%.aarch64.out : %.aarch64.c
	@echo "[+] Building '$@'"
	@aarch64-linux-gnu-gcc $(CFLAGS) $(EXTRA_FLAGS) -w -o $@ $< $(LDFLAGS)

%.riscv64.out : %.riscv64.c
	@echo "[+] Building '$@'"
	@riscv64-linux-gnu-gcc -march=rv64gc -mabi=lp64d -g $(CFLAGS) $(EXTRA_FLAGS) -w -o $@ $? $(LDFLAGS)

# AARCH64_SOURCES := $(wildcard *.aarch64.c)
# AARCH64_TARGETS := $(AARCH64_SOURCES:.aarch64.c=.aarch64.out)

# RISCV64_SOURCES := $(wildcard *.riscv64.c)
# RISCV64_TARGETS := $(RISCV64_SOURCES:.riscv64.c=.riscv64.out)


all: $(BASIC_C_TARGETS) reference-binary.aarch64.out reference-binary.riscv64.out

clean:
	rm -f *.aarch64.out *.arm.out *.riscv64.out *.mips64.out *.mips32.out
