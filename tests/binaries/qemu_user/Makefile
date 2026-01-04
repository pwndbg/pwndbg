.PHONY: all

ZIGCC = uv run python3 -m ziglang cc

# In case we ever need a different compiler for an arch, fill it in here:
CC.aarch64 = ${ZIGCC}
CC.arm = ${ZIGCC}
CC.riscv32 = ${ZIGCC}
CC.riscv64 = ${ZIGCC}
CC.mips32 = ${ZIGCC}
CC.mipsel32 = ${ZIGCC}
CC.mips64el = ${ZIGCC}
CC.loongarch64 = ${ZIGCC}
CC.s390x = ${ZIGCC}
CC.powerpc32 = ${ZIGCC}
CC.powerpc64 = ${ZIGCC}
CC.powerpc64le = ${ZIGCC}
CC.sparc64 = ${ZIGCC}

ALL_FLAGS = -g

# These flags should be used when compiling a program that uses LIBC
# Note the list of architectures that musl supports: https://wiki.musl-libc.org/supported-platforms
CFLAGS.aarch64 = $(ALL_FLAGS) --target=aarch64-linux-musl
CFLAGS.arm = $(ALL_FLAGS) --target=arm-linux-musleabihf
CFLAGS.riscv32 = $(ALL_FLAGS) --target=riscv32-linux-musl
CFLAGS.riscv64 = $(ALL_FLAGS) --target=riscv64-linux-musl
CFLAGS.mips32 = $(ALL_FLAGS) --target=mips-linux-musleabi # Big-endian MIPS
CFLAGS.mipsel32 = $(ALL_FLAGS) --target=mipsel-linux-musleabi # Little-endian MIPS
CFLAGS.mips64el = $(ALL_FLAGS) --target=mips64el-linux-muslabi64
CFLAGS.loongarch64 = $(ALL_FLAGS) --target=loongarch64-linux-musl
CFLAGS.s390x = $(ALL_FLAGS) --target=s390x-linux-musl -mcpu=z13
CFLAGS.powerpc32 = $(ALL_FLAGS) --target=powerpc-linux-musl
CFLAGS.powerpc64 = $(ALL_FLAGS) --target=powerpc64-linux-musl
CFLAGS.powerpc64le = $(ALL_FLAGS) --target=powerpc64le-linux-musl


AARCH64_SOURCES := $(wildcard *.aarch64.c)
AARCH64_TARGETS := $(AARCH64_SOURCES:.aarch64.c=.aarch64.out)

ARM_SOURCES := $(wildcard *.arm.c)
ARM_TARGETS := $(ARM_SOURCES:.arm.c=.arm.out)

RISCV32_SOURCES := $(wildcard *.riscv32.c)
RISCV32_TARGETS := $(RISCV32_SOURCES:.riscv32.c=.riscv32.out)

RISCV64_SOURCES := $(wildcard *.riscv64.c)
RISCV64_TARGETS := $(RISCV64_SOURCES:.riscv64.c=.riscv64.out)

MIPS32_SOURCES := $(wildcard *.mips32.c)
MIPS32_TARGETS := $(MIPS32_SOURCES:.mips32.c=.mips32.out)

MIPSEL32_SOURCES := $(wildcard *.mipsel32.c)
MIPSEL32_TARGETS := $(MIPSEL32_SOURCES:.mipsel32.c=.mipsel32.out)

MIPS64EL_SOURCES := $(wildcard *.mips64el.c)
MIPS64EL_TARGETS := $(MIPS64EL_SOURCES:.mips64el.c=.mips64el.out)

LOONGARCH64_SOURCES := $(wildcard *.loongarch64.c)
LOONGARCH64_TARGETS := $(LOONGARCH64_SOURCES:.loongarch64.c=.loongarch64.out)

S390X_SOURCES := $(wildcard *.s390x.c)
S390X_TARGETS := $(S390X_SOURCES:.s390x.c=.s390x.out)

POWERPC32_SOURCES := $(wildcard *.powerpc32.c)
POWERPC32_TARGETS := $(POWERPC32_SOURCES:.powerpc32.c=.powerpc32.out)

POWERPC64_SOURCES := $(wildcard *.powerpc64.c)
POWERPC64_TARGETS := $(POWERPC64_SOURCES:.powerpc64.c=.powerpc64.out)

SPARC64_SOURCES := $(wildcard *.sparc64.c)
SPARC64_TARGETS := $(SPARC64_SOURCES:.sparc64.c=.sparc64.out)


ARCHES_TO_COMPILE_BASIC = aarch64 arm riscv32 riscv64 mips32 mipsel32 mips64el loongarch64 s390x powerpc64le
# Build basic.c (which relies on libc) for these architectures
BASIC_C_TARGETS = $(ARCHES_TO_COMPILE_BASIC:%=basic.%.out)
basic.%.out: basic.c
	@echo "[+] Building '$@'"
	$(CC.$*) $(CFLAGS.$*) -o $@ $<


%.aarch64.out : %.aarch64.c
	@echo "[+] Building '$@'"
	$(CC.aarch64) $(CFLAGS.aarch64) -o $@ $<

%.riscv64.out : %.riscv64.c
	@echo "[+] Building '$@'"
	$(CC.riscv64) $(CFLAGS.riscv64) -o $@ $?


all: $(BASIC_C_TARGETS) $(AARCH64_TARGETS) $(ARM_TARGETS) $(RISCV32_TARGETS) $(RISCV64_TARGETS) $(MIPS32_TARGETS) $(MIPSEL32_TARGETS) $(MIPS64EL_TARGETS) $(LOONGARCH64_TARGETS) $(S390X_TARGETS) $(POWERPC32_TARGETS) $(POWERPC64_TARGETS)

clean:
	rm -f $(BASIC_C_TARGETS) $(AARCH64_TARGETS) $(ARM_TARGETS) $(RISCV32_TARGETS) $(RISCV64_TARGETS) $(MIPS32_TARGETS) $(MIPSEL32_TARGETS) $(MIPS64EL_TARGETS) $(LOONGARCH64_TARGETS) $(S390X_TARGETS) $(POWERPC32_TARGETS) $(POWERPC64_TARGETS)
