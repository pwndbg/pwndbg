subdirs=xenial stable $(wildcard */)
makefiles=$(wildcard */Makefile)
tags=stable beta dev

all: $(makefiles) $(subdirs)

$(subdirs):
	docker build -t pwndbg/pwndbg:$(shell basename $(@)) "$@"

$(makefiles):
	make -C $(shell dirname $@)

.PHONY: all $(subdirs) $(makefiles)
