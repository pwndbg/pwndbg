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
COMPILED_GO     =	   $(SOURCES_GO:.go=)

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

all: $(LINKED) $(LINKED_ASM) $(COMPILED_GO)


%.out : %.c
	@echo "[+] Building '$@'"
	@$(CC) $(CFLAGS) $(EXTRA_FLAGS) -w -o $@ $? $(LDFLAGS)

%.o : %.asm
	@echo "[+] Building '$@'"
	@$(NASM) $(EXTRA_FLAGS_ASM) -o $@ $?

%.out : %.o
	@echo "[+] Linking '$@'"
	@$(LD) -Ttext 0x400080 --section-start .note.gnu.property=0x8000000 -o $@ $?

%.x86 : %.x86.go
	@echo "[+] Building '$@'"
	@GOARCH=386 $(GO) build $?
	@# Not stripped on purpose

%.x64 : %.x64.go
	@echo "[+] Building '$@'"
	@GOARCH=amd64 $(GO) build $?
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

clean :
	@echo "[+] Cleaning stuff"
	@rm -f $(COMPILED) $(LINKED) $(COMPILED_ASM) $(LINKED_ASM) $(COMPILED_GO)


reference-binary.out: EXTRA_FLAGS := -Dexample=1
