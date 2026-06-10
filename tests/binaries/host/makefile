HOST_ARCH := $(shell uname -m)
HOST_ARCH_32 := empty

ifeq ($(HOST_ARCH),x86_64)
    HOST_ARCH = x86-64

    # Not all kernels support IA32, it can be disabled `ia32_emulation=off` OR `CONFIG_IA32=n`
    IA32_OK := $(shell ./check_ia32.i386.out.hardcoded >/dev/null 2>&1 && echo yes || echo no)
    ifeq ($(IA32_OK),yes)
        HOST_ARCH_32 := i386
    endif
else ifeq ($(HOST_ARCH),i686)
    HOST_ARCH := i386
endif

# Per-arch names for the libc version-test binaries. x86-64 and aarch64 are both
# 64-bit, so the tests themselves are arch-portable; only the loader name and the zig
# target triple differ. LIBC_VER_ARCH_OK gates the glibc/musl version targets.
ifeq ($(HOST_ARCH),x86-64)
    LIBC_VER_ARCH_OK := yes
    MUSL_DYNAMIC_OK  := yes
    GLIBC_LD_NAME    := ld-linux-x86-64.so.2
    MUSL_LD_NAME     := ld-musl-x86_64.so.1
    ZIG_LIBC_TARGET  := x86_64-linux-gnu
else ifeq ($(HOST_ARCH),aarch64)
    LIBC_VER_ARCH_OK := yes
    # The hand-built zig + crt + .interp dynamic musl link is x86-64-tuned; those
    # binaries fail to launch under gdb on aarch64. Static musl (self-contained)
    # still covers mallocng on arm, so build dynamic musl x86-64 only.
    MUSL_DYNAMIC_OK  := no
    GLIBC_LD_NAME    := ld-linux-aarch64.so.1
    MUSL_LD_NAME     := ld-musl-aarch64.so.1
    ZIG_LIBC_TARGET  := aarch64-linux-gnu
else
    LIBC_VER_ARCH_OK := no
endif

ZIGCC           = uv run python3 -m ziglang cc
PKG_CONFIG      ?=     pkg-config
CC              =      gcc
CXX             =      g++
MUSLCC          =      musl-gcc
DEBUG           =      1
CFLAGS         +=      -Wall
# bionic_probe.native.c is built by the NDK inside Dockerfile.bionic-test-libs (the
# binaries ship prebuilt); a host-glibc build of it would just be an unused artifact.
SOURCES_C       =      $(filter-out bionic_probe.native.c,$(wildcard *.native.c)) $(wildcard *.$(HOST_ARCH).c) $(wildcard *.$(HOST_ARCH_32).c)
LINKED_C        =      $(SOURCES_C:.c=.out)

NASM            =      nasm -f elf64
LD              =      ld
SOURCES_ASM     =      $(wildcard *.$(HOST_ARCH).asm) $(wildcard *.$(HOST_ARCH_32).asm)
LINKED_ASM      =      $(SOURCES_ASM:.asm=.out)

GO              =      go
SOURCES_GO      =      $(wildcard *.native.go) $(wildcard *.$(HOST_ARCH).go) $(wildcard *.$(HOST_ARCH_32).go)
LINKED_GO       =      $(SOURCES_GO:.go=.out)

HAVE_JEMALLOC := $(shell $(PKG_CONFIG) --exists jemalloc && echo yes || echo no)
ifeq ($(HAVE_JEMALLOC),yes)
JEMALLOC_CFLAGS := $(shell $(PKG_CONFIG) --cflags jemalloc)
JEMALLOC_LIBS   := $(shell $(PKG_CONFIG) --libs jemalloc)
endif

# musl is "available" only if musl-gcc actually compiles+links a trivial program.
# Some distros (e.g. Arch) ship a musl-gcc whose spec is broken against the current
# GCC, so an existence check alone is not enough.
HAVE_MUSL := $(shell printf 'int main(void){return 0;}' | $(MUSLCC) -x c -o /dev/null - >/dev/null 2>&1 && echo yes || echo no)

ifeq ($(DEBUG), 1)
CFLAGS         +=      -DDEBUG=1 -ggdb -O0 -gdwarf-4
else
CFLAGS         +=      -O1
endif

# LLDB does not support PLT symbolication with -fcf-protection :(
CFLAGS         += -fcf-protection=none
CFLAGS         += -fno-sanitize=all

PWD=$(shell pwd)
# Apparently we don't have this version? :(
#GLIBC=/glibc_versions/2.29/tcache_x64
GLIBC_2_33=$(PWD)/glibcs/2.33

.PHONY : all clean

ALL_JEMALLOC_TARGETS :=
ifeq ($(HAVE_JEMALLOC),yes)
ALL_JEMALLOC_TARGETS += heap_jemalloc_extent_info.native.out heap_jemalloc_heap.native.out
endif

ALL_MUSL_TARGETS :=
ifeq ($(HAVE_MUSL),yes)
ALL_MUSL_TARGETS += heap_musl_dyn.native.out heap_musl_static.native.out heap_musl_static_stripped.native.out
endif

# --- Glibc multi-version heap test binaries ---
# Build each binary in GLIBC_HEAP_BINARIES against every glibc version that has
# artifacts in glibcs/<ver>/ (downloaded by scripts/download-test-libs.sh glibc).
# To target a new binary: add its base name (foo -> foo.native.c) to
# GLIBC_HEAP_BINARIES. Which versions a test exercises is chosen test-side
# via @pytest.mark.parametrize.
# Versions parsed from Dockerfile.glibc-test-libs (its build-<ver> stages).
GLIBC_TEST_VERSIONS := $(shell sed -n 's/^FROM base-builder AS build-\([0-9][0-9.]*\).*/\1/p' $(PWD)/../../../Dockerfile.glibc-test-libs)
GLIBC_HEAP_BINARIES := heap_malloc_chunk heap_malloc_chunk_dump heap_bins heap_find_fake_fast

# Only versions whose artifacts are actually present on disk get built.
AVAILABLE_GLIBC_VERSIONS := $(foreach ver,$(GLIBC_TEST_VERSIONS),\
    $(if $(wildcard $(PWD)/glibcs/$(ver)/$(GLIBC_LD_NAME)),$(ver)))

# One build rule per (binary, version).
# $(1) = binary base name, $(2) = glibc version
ifeq ($(LIBC_VER_ARCH_OK),yes)
ifeq ($(strip $(GLIBC_TEST_VERSIONS)),)
$(error Could not parse glibc versions from Dockerfile.glibc-test-libs - expected 'FROM base-builder AS build-<ver>' stages)
endif
define GLIBC_HEAP_TARGET
$(1).glibc-$(2).out: $(1).native.c
	@echo "[+] Building '$$@' against glibc $(2)"
	$${ZIGCC} $${CFLAGS} -w \
	-target $(ZIG_LIBC_TARGET).$(2) \
	-Wl,-rpath=$$(PWD)/glibcs/$(2) \
	-Wl,--dynamic-linker=$$(PWD)/glibcs/$(2)/$(GLIBC_LD_NAME) \
	-o $$@ $$< -pthread -lpthread
endef

$(foreach bin,$(GLIBC_HEAP_BINARIES),\
    $(foreach ver,$(AVAILABLE_GLIBC_VERSIONS),\
        $(eval $(call GLIBC_HEAP_TARGET,$(bin),$(ver)))))

ALL_GLIBC_VERSION_TARGETS := $(foreach bin,$(GLIBC_HEAP_BINARIES),\
    $(foreach ver,$(AVAILABLE_GLIBC_VERSIONS),$(bin).glibc-$(ver).out))

# No-debug glibc variants (linked against glibcs-nodebug/<ver>/, a stripped libc with
# no .gnu_debuglink) so pwndbg must resolve the heap heuristically with no libc symbols.
# Only heap_malloc_chunk needs one (the heuristic + version test target).
GLIBC_NODEBUG_BINARIES := heap_malloc_chunk
AVAILABLE_GLIBC_NODEBUG_VERSIONS := $(foreach ver,$(GLIBC_TEST_VERSIONS),\
    $(if $(wildcard $(PWD)/glibcs-nodebug/$(ver)/$(GLIBC_LD_NAME)),$(ver)))

define GLIBC_HEAP_NODEBUG_TARGET
$(1).glibc-$(2)-nodebug.out: $(1).native.c
	@echo "[+] Building '$$@' against no-debug glibc $(2)"
	$${ZIGCC} $${CFLAGS} -w \
	-target $(ZIG_LIBC_TARGET).$(2) \
	-Wl,-rpath=$$(PWD)/glibcs-nodebug/$(2) \
	-Wl,--dynamic-linker=$$(PWD)/glibcs-nodebug/$(2)/$(GLIBC_LD_NAME) \
	-o $$@ $$< -pthread -lpthread
endef

$(foreach bin,$(GLIBC_NODEBUG_BINARIES),\
    $(foreach ver,$(AVAILABLE_GLIBC_NODEBUG_VERSIONS),\
        $(eval $(call GLIBC_HEAP_NODEBUG_TARGET,$(bin),$(ver)))))

ALL_GLIBC_VERSION_TARGETS += $(foreach bin,$(GLIBC_NODEBUG_BINARIES),\
    $(foreach ver,$(AVAILABLE_GLIBC_NODEBUG_VERSIONS),$(bin).glibc-$(ver)-nodebug.out))
else
ALL_GLIBC_VERSION_TARGETS :=
endif
# --- End glibc multi-version targets ---

# --- Musl multi-version heap test binaries (static + dynamic) ---
# Versions parsed from Dockerfile.musl-test-libs (its build-<ver> stages).
MUSL_TEST_VERSIONS := $(shell sed -n 's/^FROM base-builder AS build-\([0-9][0-9.]*\).*/\1/p' $(PWD)/../../../Dockerfile.musl-test-libs)
MUSL_HEAP_BINARIES := heap_musl

# Only versions whose artifacts are actually present on disk get built.
AVAILABLE_MUSL_VERSIONS := $(foreach ver,$(MUSL_TEST_VERSIONS),\
    $(if $(wildcard $(PWD)/musls/$(ver)/lib/libc.a),$(ver)))

# Static detection relies on the mallocng allocator signature, which musl gained
# in 1.2.1; older versions are fingerprintable only when dynamically linked
# (mirrors _MALLOCNG_MIN in test_musl_versions.py). So the static binary is built
# only for >= 1.2.1, while the dynamic one is built for every available version.
MUSL_MALLOCNG_MIN := 1.2.1
MUSL_STATIC_VERSIONS := $(shell printf '%s\n' $(AVAILABLE_MUSL_VERSIONS) | \
    awk -F. -v min="$(MUSL_MALLOCNG_MIN)" 'BEGIN{split(min,m,".")} \
    ($$1>m[1])||($$1==m[1]&&$$2>m[2])||($$1==m[1]&&$$2==m[2]&&$$3>=m[3])')

ifeq ($(LIBC_VER_ARCH_OK),yes)
ifeq ($(strip $(MUSL_TEST_VERSIONS)),)
$(error Could not parse musl versions from Dockerfile.musl-test-libs - expected 'FROM base-builder AS build-<ver>' stages)
endif
# zig cc is the driver only (it can't pick a musl version), so we link explicitly
# against the version's own crt objects + libc, with its headers via -isystem.
# Those artifacts are prerequisites too, so a re-downloaded artifact tree triggers
# a relink (what the linker records, e.g. the SONAME, can change between builds).
# Static: force in the otherwise-unreferenced __libc_version with -Wl,-u so
# pwndbg's version() can read it straight from the binary.
define MUSL_HEAP_STATIC_TARGET
$(1).musl-$(2)-static.out: $(1).native.c $(PWD)/musls/$(2)/lib/libc.a $(PWD)/musls/$(2)/lib/crt1.o $(PWD)/musls/$(2)/lib/crti.o $(PWD)/musls/$(2)/lib/crtn.o
	@echo "[+] Building '$$@' against musl $(2) (static)"
	$${ZIGCC} $${CFLAGS} -static -no-pie -fno-pie -nostdlibinc -nostdlib \
	-isystem $$(PWD)/musls/$(2)/include \
	-Wl,-u,__libc_version \
	-o $$@ \
	$$(PWD)/musls/$(2)/lib/crt1.o $$(PWD)/musls/$(2)/lib/crti.o \
	$$< \
	$$(PWD)/musls/$(2)/lib/libc.a $$(PWD)/musls/$(2)/lib/crtn.o
endef

# Dynamic: link against the version's libc.so with -rpath so it loads that exact
# musl at runtime. The interpreter is set via a .interp section emitted from the
# source (-DMUSL_DYNAMIC_INTERP), NOT -Wl,--dynamic-linker: the pinned zig 0.14.1
# lld silently drops that flag for a -nostdlib link, yielding a binary with no
# PT_INTERP that never loads libc (so pwndbg reads it as statically linked).
define MUSL_HEAP_DYNAMIC_TARGET
$(1).musl-$(2)-dynamic.out: $(1).native.c $(PWD)/musls/$(2)/lib/libc.so $(PWD)/musls/$(2)/lib/crt1.o $(PWD)/musls/$(2)/lib/crti.o $(PWD)/musls/$(2)/lib/crtn.o
	@echo "[+] Building '$$@' against musl $(2) (dynamic)"
	$${ZIGCC} $${CFLAGS} -no-pie -fno-pie -nostdlibinc -nostdlib \
	-isystem $$(PWD)/musls/$(2)/include \
	-DMUSL_DYNAMIC_INTERP=\"$$(PWD)/musls/$(2)/lib/$(MUSL_LD_NAME)\" \
	-Wl,-rpath=$$(PWD)/musls/$(2)/lib \
	-o $$@ \
	$$(PWD)/musls/$(2)/lib/crt1.o $$(PWD)/musls/$(2)/lib/crti.o \
	$$< \
	$$(PWD)/musls/$(2)/lib/libc.so $$(PWD)/musls/$(2)/lib/crtn.o
endef

$(foreach bin,$(MUSL_HEAP_BINARIES),\
    $(foreach ver,$(MUSL_STATIC_VERSIONS),\
        $(eval $(call MUSL_HEAP_STATIC_TARGET,$(bin),$(ver)))))

ALL_MUSL_VERSION_TARGETS := $(foreach bin,$(MUSL_HEAP_BINARIES),\
    $(foreach ver,$(MUSL_STATIC_VERSIONS),$(bin).musl-$(ver)-static.out))

# Dynamic musl binaries are x86-64 only (see MUSL_DYNAMIC_OK above); on aarch64 the
# tests skip the missing dynamic binaries and run the static ones.
ifeq ($(MUSL_DYNAMIC_OK),yes)
$(foreach bin,$(MUSL_HEAP_BINARIES),\
    $(foreach ver,$(AVAILABLE_MUSL_VERSIONS),\
        $(eval $(call MUSL_HEAP_DYNAMIC_TARGET,$(bin),$(ver)))))
ALL_MUSL_VERSION_TARGETS += $(foreach bin,$(MUSL_HEAP_BINARIES),\
    $(foreach ver,$(AVAILABLE_MUSL_VERSIONS),$(bin).musl-$(ver)-dynamic.out))
endif
else
ALL_MUSL_VERSION_TARGETS :=
endif
# --- End musl multi-version targets ---

CUSTOM_TARGETS = heap_find_fake_fast.native.out reference_bin_pie.native.out reference_bin_nopie.native.out reference_bin_nopie.i386.out symbol_1600_and_752.native.out initialized_heap.x86-64.out initialized_heap_big.i386.out linked_lists.native.out onegadget.x86-64.out onegadget.i386.out heap_musl_dyn.native.out heap_musl_static.native.out heap_musl_static_stripped.native.out gosample.i386.out gosample.x86-64.out
NATIVE_CUSTOM_TARGETS  := $(filter %.native.out %.$(HOST_ARCH).out %.$(HOST_ARCH_32).out,$(CUSTOM_TARGETS))

ALL_TARGETS := $(LINKED_C) $(LINKED_ASM) $(LINKED_GO) $(NATIVE_CUSTOM_TARGETS) \
    $(ALL_JEMALLOC_TARGETS) \
    $(ALL_MUSL_TARGETS) \
    $(ALL_GLIBC_VERSION_TARGETS) \
    $(ALL_MUSL_VERSION_TARGETS)

all: $(ALL_TARGETS)

%.out : %.c
	@echo "[+] Building '$@'"
	${ZIGCC} ${CFLAGS} -w -o $@ $?

%.out : %.asm
	@echo "[+] Building '$@'"
	@$(NASM) -o $@.o $?
	@$(LD) -Ttext 0x400080 --section-start .note.gnu.property=0x8000000 -o $@ $@.o

%.out : %.go
	@echo "[+] Building '$@'"
	@$(GO) build -gcflags "-N -l" -o $@ $?
	@# Not stripped on purpose

check_ia32.i386.out.hardcoded: check_ia32.i386.c
	@echo "[+] Building IA-32 check binary"
	${ZIGCC} -target x86-linux-gnu -Os -o $@ $<

crash_simple.native.out: crash_simple.native.c
	@echo "[+] Building '$@'"
	${ZIGCC} -O0 -nostdlib -ffreestanding -fno-stack-protector -fno-sanitize=all -o $@ $?

div_zero.native.out: div_zero.native.c
	@echo "[+] Building '$@'"
	${ZIGCC} -g -ggdb -O0 -gdwarf-4 -fsanitize-trap=undefined -Wno-division-by-zero -o $@ $?

gosample.i386.out : gosample.native.go
	@echo "[+] Building '$@'"
	@GOARCH=386 $(GO) build -gcflags "-N -l" -o $@ $?
	@# Not stripped on purpose

gosample.x86-64.out : gosample.native.go
	@echo "[+] Building '$@'"
	@GOARCH=amd64 $(GO) build -gcflags "-N -l" -o $@ $?
	@# Not stripped on purpose

heap_bugs.x86-64.out: heap_bugs.x86-64.c
	@echo "[+] Building '$@'"
	${ZIGCC} \
	${CFLAGS} \
	-Wno-int-to-pointer-cast -Wno-int-conversion -Wno-unused-variable \
	-target x86_64-linux-gnu.2.33 \
	-Wl,-rpath=${GLIBC_2_33}:\
	-Wl,--dynamic-linker=${GLIBC_2_33}/ld-linux-x86-64.so.2 \
	-o $@ $?

# TODO/FIXME: We should probably force this to 2.29? a version with tcache?
#heap_bins.out: heap_bins.c
#	@echo "[+] Building '$@'"
#	${ZIGCC} \
#	-target x86_64-linux-gnu.2.33 \
#	-Wl,-rpath=${GLIBC_2_33} \
#	-Wl,--dynamic-linker=${GLIBC_2_33}/ld-linux-x86-64.so.2 \
#	-g -O0 -o $@ $?

# Note: we use -pthread -lpthread because we hit this bug on CI builds:
# https://sourceware.org/bugzilla/show_bug.cgi?id=24548
heap_vis.native.out: heap_vis.native.c
	@echo "[+] Building '$@'"
	${ZIGCC} ${CFLAGS} -g -O0 -Wno-nonnull -o $@ $? -pthread -lpthread

heap_malloc_chunk.native.out: heap_malloc_chunk.native.c
	@echo "[+] Building '$@'"
	${ZIGCC} ${CFLAGS} -g -O0 -Wno-nonnull -Wno-unused-result -o $@ $? -pthread -lpthread

heap_find_fake_fast.native.out: heap_find_fake_fast.native.c
	@echo "[+] Building '$@'"
	${CC} ${CFLAGS} -w -o $@ $? -pthread -lpthread

ifeq ($(HAVE_JEMALLOC),yes)

heap_jemalloc_extent_info.native.out: heap_jemalloc_extent_info.native.c
	@echo "[+] Building '$@'"
	${ZIGCC} -g -O0 -Wno-nonnull -Wno-unused-result \
	$(JEMALLOC_CFLAGS) \
	-o $@ $? \
	-Wl,-Bstatic $(JEMALLOC_LIBS) -Wl,-Bdynamic -lpthread -lm -lstdc++ -pthread -ldl

heap_jemalloc_heap.native.out: heap_jemalloc_heap.native.c
	@echo "[+] Building '$@'"
	${ZIGCC} -g -O0 -Wno-nonnull -Wno-unused-result \
	$(JEMALLOC_CFLAGS) \
	-o $@ $? \
	-Wl,-Bstatic $(JEMALLOC_LIBS) -Wl,-Bdynamic -lpthread -lm -lstdc++ -pthread -ldl

else

heap_jemalloc_extent_info.native.out: heap_jemalloc_extent_info.native.c
	@echo "[!] Skip '$@'"

heap_jemalloc_heap.native.out: heap_jemalloc_heap.native.c
	@echo "[!] Skip '$@'"

$(info [!] jemalloc not found via $(PKG_CONFIG) – skipping jemalloc targets)

endif


ifeq ($(HAVE_MUSL),yes)

heap_musl_dyn.native.out: heap_musl.native.c
	@echo "[+] Building '$@'"
	${MUSLCC} -g3 -O0 -o $@ $?

# Ideally I would do:
# strip heap_musl_static.out
# here because it would ensure mallocng commands are tested on
# a musl with no symbols. But that also makes it very hard to
# write the tests.
heap_musl_static.native.out: heap_musl.native.c
	@echo "[+] Building '$@'"
	${MUSLCC} -g3 -O0 -static -o $@ $?

# Same as above but with debug info stripped (keeping the symbol table).
# Used by the musl detection test so that has_debug_info() is consistently
# False across distros. On Fedora 43, -g3 caused struct __ptcb to appear in
# debug info, while on other distros it didn't.
heap_musl_static_stripped.native.out: heap_musl.native.c
	@echo "[+] Building '$@'"
	${MUSLCC} -g3 -O0 -static -o $@ $?
	strip --strip-debug $@

else

heap_musl_dyn.native.out: heap_musl.native.c
	@echo "[!] Skip '$@'"

heap_musl_static.native.out: heap_musl.native.c
	@echo "[!] Skip '$@'"

heap_musl_static_stripped.native.out: heap_musl.native.c
	@echo "[!] Skip '$@'"

$(info [!] musl compiler not found ($(MUSLCC)) – skipping musl targets)

endif

multiple_threads.native.out: multiple_threads.native.c
	@echo "[+] Building '$@'"
	${ZIGCC} -g -O0 -o $@ $? -pthread -lpthread

tls.x86-64.out: tls.x86-64.c
	@echo "[+] Building '$@'"
	${ZIGCC} \
	${CFLAGS} \
	-target x86_64-linux-gnu \
	-o $@ $?

tls.i386.out: tls.i386.c
	@echo "[+] Building '$@'"
	${ZIGCC} \
	${CFLAGS} \
	-target x86-linux-gnu \
	-o $@ $?

issue_1565.native.out: issue_1565.native.c
	@echo "[+] Building '$@'"
	${ZIGCC} -g -O0 -o $@ $? -pthread -lpthread

# TODO: Link against a specific GLIBC version >= 2.26
initialized_heap_big.i386.out: initialized_heap.native.c
	@echo "[+] Building '$@'"
	${ZIGCC} \
	${CFLAGS} \
	-target x86-linux-gnu \
	-o $@ $?

# TODO: Link against a specific GLIBC version.
initialized_heap.x86-64.out: initialized_heap.native.c
	@echo "[+] Building '$@'"
	${ZIGCC} \
	${CFLAGS} \
	-target x86_64-linux-gnu \
	-o $@ $?

onegadget.x86-64.out: onegadget.native.c
	@echo "[+] Building '$@'"
	${ZIGCC} \
	${CFLAGS} \
	-target x86_64-linux-gnu \
	-o $@ $?

onegadget.i386.out: onegadget.native.c
	@echo "[+] Building '$@'"
	${ZIGCC} \
	${CFLAGS} \
	-target x86-linux-gnu \
	-o $@ $?

clean :
	@echo "[+] Cleaning stuff"
	@rm -f $(LINKED_C) $(LINKED_ASM) $(LINKED_GO) *.out *.o

linked_lists.native.out: linked-lists.native.c
	@echo "[+] Building '$@'"
	${ZIGCC} -fpie -g -o $@ $?

reference_bin_pie.native.out: reference-binary.native.c
	@echo "[+] Building '$@'"
	${ZIGCC} -fpie -o $@ $?

reference_bin_nopie.native.out: reference-binary.native.c
	@echo "[+] Building '$@'"
	${ZIGCC} -fno-pie -o $@ $?

reference_bin_nopie.i386.out: reference-binary.native.c
	@echo "[+] Building '$@'"
	${ZIGCC} -fno-pie -target x86-linux-gnu -o $@ $?

symbol_1600_and_752.native.out: symbol_1600_and_752.native.cpp
	${CXX} -O0 -ggdb -Wno-pmf-conversions -o $@ $?

canary.x86-64.out: canary.x86-64.c
	@echo "[+] Building '$@'"
	${ZIGCC} \
	${CFLAGS} \
	-target x86_64-linux-gnu \
	-o $@ $?

canary.i386.out: canary.i386.c
	@echo "[+] Building '$@'"
	${ZIGCC} \
	${CFLAGS} \
	-target x86-linux-gnu \
	-o $@ $?

pku.i386.out: pku.x86_64.c
	@echo "[+] Building '$@'"
	${ZIGCC} \
	${CFLAGS} \
	-target x86_64-linux-gnu \
	-o $@ $?
