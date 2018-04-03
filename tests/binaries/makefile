CC              =       gcc
DEBUG           =       1
CFLAGS         +=       -Wall
SOURCES         =       $(wildcard *.c)
COMPILED        =       $(SOURCES:.c=.o)
LINKED          =       $(SOURCES:.c=.out)
LDFLAGS         =
EXTRA_FLAGS	    =

ifeq ($(TARGET), x86)
CFLAGS          +=      -m32
endif

ifeq ($(DEBUG), 1)
CFLAGS          +=      -DDEBUG=1 -ggdb -O0
else
CFLAGS          +=      -O1
endif


.PHONY : all clean

all: $(LINKED)


%.out : %.c
	@echo "[+] Building '$@'"
	@$(CC) $(CFLAGS) $(EXTRA_FLAGS) -o $@ $? $(LDFLAGS)

clean :
	@echo "[+] Cleaning stuff"
	@rm -f $(COMPILED) $(LINKED)


reference-binary.out: EXTRA_FLAGS := -Dexample=1

