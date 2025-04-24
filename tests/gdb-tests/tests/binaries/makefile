ZIGPATH        ?=     ../../../../.zig
ZIGCC		=	  $(ZIGPATH)/zig cc

CC              =	   gcc
DEBUG           =	   1
CFLAGS         +=	   -Wall
SOURCES         =	   $(wildcard *.c)
COMPILED        =	   $(SOURCES:.c=.o)
LINKED          =	   $(SOURCES:.c=.out)

NASM            =	   nasm -f elf64
LD              =	   ld
SOURCES_ASM     =	   $(wildcard *.asm)
COMPILED_ASM    =	   $(SOURCES_ASM:.asm=.o)
LINKED_ASM      =	   $(SOURCES_ASM:.asm=.out)
LDFLAGS         =
EXTRA_FLAGS     =
EXTRA_FLAGS_ASM =

GO              =	   go
SOURCES_GO      =	   $(wildcard *.go)
COMPILED_GO     =	   $(SOURCES_GO:.go=.x86) $(SOURCES_GO:.go=.x64)

ifeq ($(TARGET), x86)
CFLAGS		  +=	  -m32
endif

ifeq ($(DEBUG), 1)
CFLAGS		  +=	  -DDEBUG=1 -ggdb -O0 -gdwarf-4
else
CFLAGS		  +=	  -O1
endif

PWD=$(shell pwd)
# Apparently we don't have this version? :(
#GLIBC=/glibc_versions/2.29/tcache_x64
GLIBC_2_33=$(PWD)/glibcs/2.33

.PHONY : all clean

CUSTOM_TARGETS = reference_bin_pie.out reference_bin_nopie.out reference_bin_nopie.i386.out symbol_1600_and_752.out initialized_heap_x64.out initialized_heap_i386_big.out linked_lists.out onegadget.x86-64.out onegadget.i386.out

all: $(LINKED) $(LINKED_ASM) $(COMPILED_GO) $(CUSTOM_TARGETS)

%.out : %.c
	@echo "[+] Building '$@'"
	@$(CC) $(CFLAGS) $(EXTRA_FLAGS) -w -o $@ $? $(LDFLAGS)

%.o : %.asm
	@echo "[+] Building '$@'"
	@$(NASM) $(EXTRA_FLAGS_ASM) -o $@ $?

%.out : %.o
	@echo "[+] Linking '$@'"
	@$(LD) -Ttext 0x400080 --section-start .note.gnu.property=0x8000000 -o $@ $?

%.x86 : %.go
	@echo "[+] Building '$@'"
	@GOARCH=386 $(GO) build -gcflags "-N -l" -o $@ $?
	@# Not stripped on purpose

%.x64 : %.go
	@echo "[+] Building '$@'"
	@GOARCH=amd64 $(GO) build -gcflags "-N -l" -o $@ $?
	@# Not stripped on purpose

heap_bugs.out: heap_bugs.c
	@echo "[+] Building heap_bugs.out"
	${ZIGCC} \
	${CFLAGS} \
	-Wno-int-to-pointer-cast -Wno-int-conversion -Wno-unused-variable \
	-target native-native-gnu.2.33 \
	-Wl,-rpath=${GLIBC_2_33}:\
	-Wl,--dynamic-linker=${GLIBC_2_33}/ld-linux-x86-64.so.2 \
	-o heap_bugs.out heap_bugs.c

# TODO/FIXME: We should probably force this to 2.29? a version with tcache?
#heap_bins.out: heap_bins.c
#	@echo "[+] Building heap_bins.out"
#	${ZIGCC} \
#	-target native-native-gnu.2.33 \
#	-Wl,-rpath=${GLIBC_2_33} \
#	-Wl,--dynamic-linker=${GLIBC_2_33}/ld-linux-x86-64.so.2 \
#	-g -O0 -o heap_bins.out heap_bins.c

# Note: we use -pthread -lpthread because we hit this bug on CI builds:
# https://sourceware.org/bugzilla/show_bug.cgi?id=24548
heap_vis.out: heap_vis.c
	@echo "[+] Building heap_vis.out"
	${CC} -g -O0 -Wno-nonnull -o heap_vis.out heap_vis.c -pthread -lpthread

heap_malloc_chunk.out: heap_malloc_chunk.c
	@echo "[+] Building heap_malloc_chunk.out"
	${CC} -g -O0 -Wno-nonnull -Wno-unused-result -o heap_malloc_chunk.out heap_malloc_chunk.c -pthread -lpthread

heap_jemalloc_extent_info.out: heap_jemalloc_extent_info.c
	@echo "[+] Building heap_jemalloc_extent_info.out"
	${CC} -g -O0 -Wno-nonnull -Wno-unused-result \
	-o heap_jemalloc_extent_info.out heap_jemalloc_extent_info.c \
	-Wl,-Bstatic -ljemalloc -Wl,-Bdynamic -lpthread -lm -lstdc++ -pthread -ldl

heap_jemalloc_heap.out: heap_jemalloc_heap.c
	@echo "[+] Building heap_jemalloc_heap.out"
	${CC} -g -O0 -Wno-nonnull -Wno-unused-result \
	-o heap_jemalloc_heap.out heap_jemalloc_heap.c \
	-Wl,-Bstatic -ljemalloc -Wl,-Bdynamic -lpthread -lm -lstdc++ -pthread -ldl


multiple_threads.out: multiple_threads.c
	@echo "[+] Building multiple_threads.out"
	${CC} -g -O0 -o multiple_threads.out multiple_threads.c -pthread -lpthread
tls.x86-64.out: tls.x86-64.c
	@echo "[+] Building tls.x86-64.c"
	${ZIGCC} \
	${CFLAGS} \
	-target x86_64-linux-gnu \
	-o tls.x86-64.out tls.x86-64.c

tls.i386.out: tls.i386.c
	@echo "[+] Building tls.i386.c"
	${ZIGCC} \
	${CFLAGS} \
	-target x86-linux-gnu \
	-o tls.i386.out tls.i386.c

issue_1565.out: issue_1565.c
	@echo "[+] Building issue_1565.out"
	${CC} -g -O0 -o issue_1565.out issue_1565.c -pthread -lpthread

# TODO: Link against a specific GLIBC version >= 2.26
initialized_heap_i386_big.out: initialized_heap.c
	@echo "[+] Building initialized_heap_i386_big.out"
	${ZIGCC} \
	${CFLAGS} \
	-target x86-linux-gnu \
	-o initialized_heap_i386_big.out initialized_heap.c

# TODO: Link against a specific GLIBC version.
initialized_heap_x64.out: initialized_heap.c
	@echo "[+] Building initialized_heap_x64.out"
	${ZIGCC} \
	${CFLAGS} \
	-target x86_64-linux-gnu \
	-o initialized_heap_x64.out initialized_heap.c

onegadget.x86-64.out: onegadget.c
	@echo "[+] Building onegadget.x86-64.out"
	${ZIGCC} \
	${CFLAGS} \
	-target x86_64-linux-gnu \
	-o onegadget.x86-64.out onegadget.c

onegadget.i386.out: onegadget.c
	@echo "[+] Building onegadget.i386.out"
	${ZIGCC} \
	${CFLAGS} \
	-target x86-linux-gnu \
	-o onegadget.i386.out onegadget.c

clean :
	@echo "[+] Cleaning stuff"
	@rm -f $(COMPILED) $(LINKED) $(COMPILED_ASM) $(LINKED_ASM) $(COMPILED_GO) *.out *.o

linked_lists.out: linked-lists.c
	@echo "[+] Building $<"
	${ZIGCC} -fpie -g -o $@ $<

reference_bin_pie.out: reference-binary.c
	@echo "[+] Building reference_bin_pie.out"
	${ZIGCC} -fpie -o reference_bin_pie.out reference-binary.c

reference_bin_nopie.out: reference-binary.c
	@echo "[+] Building reference_bin_nopie.out"
	${ZIGCC} -fno-pie -o reference_bin_nopie.out reference-binary.c

reference_bin_nopie.i386.out: reference-binary.c
	@echo "[+] Building reference_bin_nopie.i386.out"
	${ZIGCC} -fpie -target x86-linux-gnu -o reference_bin_nopie.i386.out reference-binary.c

symbol_1600_and_752.out: symbol_1600_and_752.cpp
	${CXX} -O0 -ggdb -Wno-pmf-conversions symbol_1600_and_752.cpp -o symbol_1600_and_752.out
