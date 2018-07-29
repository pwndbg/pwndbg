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

ifeq ($(TARGET), x86)
CFLAGS		  +=	  -m32
endif

ifeq ($(DEBUG), 1)
CFLAGS		  +=	  -DDEBUG=1 -ggdb -O0
else
CFLAGS		  +=	  -O1
endif


.PHONY : all clean

all: $(LINKED) $(LINKED_ASM)


%.out : %.c
	@echo "[+] Building '$@'"
	@$(CC) $(CFLAGS) $(EXTRA_FLAGS) -o $@ $? $(LDFLAGS)

%.o : %.asm
	@echo "[+] Building '$@'"
	@$(NASM) $(EXTRA_FLAGS_ASM) -o $@ $?

%.out : %.o
	@echo "[+] Linking '$@'"
	@$(LD) -o $@ $?

clean :
	@echo "[+] Cleaning stuff"
	@rm -f $(COMPILED) $(LINKED)


reference-binary.out: EXTRA_FLAGS := -Dexample=1
