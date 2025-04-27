.PHONY: all

ARCHS = aarch64 arm riscv64 mips64 mips32

CC.aarch64 = aarch64-linux-gnu-gcc
CC.arm = arm-linux-gnueabihf-gcc
CC.riscv64 = riscv64-linux-gnu-gcc
# Ubuntu riscv64 cross compiler package doesn't have "--enable-multilib" enabled to allow compiling to 32-bit
# CC.riscv32 = riscv64-linux-gnu-gcc
CC.mips64 = mips64-linux-gnuabi64-gcc
CC.mips32 = mips-linux-gnu-gcc
# CC.loongarch64 = loongarch64-linux-gnu-gcc

ALL_FLAGS = -g

CFLAGS.aarch64 = $(ALL_FLAGS)
CFLAGS.arm = $(ALL_FLAGS)
CFLAGS.riscv64 = -march=rv64gc -mabi=lp64d $(ALL_FLAGS)
# CFLAGS.riscv32 = -march=rv32gc $(ALL_FLAGS)
CFLAGS.mips64 = $(ALL_FLAGS)
CFLAGS.mips32 = $(ALL_FLAGS)
# CFLAGS.loongarch64 = $(ALL_FLAGS)


AARCH64_SOURCES := $(wildcard *.aarch64.c)
AARCH64_TARGETS := $(AARCH64_SOURCES:.aarch64.c=.aarch64.out)

ARM_SOURCES := $(wildcard *.arm.c)
ARM_TARGETS := $(ARM_SOURCES:.arm.c=.arm.out)

RISCV64_SOURCES := $(wildcard *.riscv64.c)
RISCV64_TARGETS := $(RISCV64_SOURCES:.riscv64.c=.riscv64.out)

MIPS64_SOURCES := $(wildcard *.mips64.c)
MIPS64_TARGETS := $(MIPS64_SOURCES:.mips64.c=.mips64.out)

MIPS32_SOURCES := $(wildcard *.mips32.c)
MIPS32_TARGETS := $(MIPS32_SOURCES:.mips32.c=.mips32.out)


# Build basic.c for all architectures
BASIC_C_TARGETS = $(ARCHS:%=basic.%.out)
basic.%.out: basic.c
	@echo "[+] Building '$@'"
	$(CC.$*) $(CFLAGS.$*) -o $@ $<


%.aarch64.out : %.aarch64.c
	@echo "[+] Building '$@'"
	$(CC.aarch64) $(CFLAGS.aarch64) -o $@ $<

%.riscv64.out : %.riscv64.c
	@echo "[+] Building '$@'"
	$(CC.riscv64) $(CFLAGS.riscv64) -o $@ $?


all: $(BASIC_C_TARGETS) $(AARCH64_TARGETS) $(ARM_TARGETS) $(RISCV64_TARGETS) $(MIPS64_TARGETS) $(MIPS32_TARGETS)

clean:
	rm -f $(BASIC_C_TARGETS) $(AARCH64_TARGETS) $(ARM_TARGETS) $(RISCV64_TARGETS) $(MIPS64_TARGETS) $(MIPS32_TARGETS)
