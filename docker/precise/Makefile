ROOT = $(shell git rev-parse --show-toplevel)
TREE = $(shell cd $(ROOT) && git stash create "docker")
ARCHIVE = $(PWD)/pwndbg.tar.gz
NAME=$(shell basename $(PWD))

ifeq ($(strip $(TREE)),)
TREE = HEAD
endif

all: image
	docker run -e --rm --init --privileged -it pwndbg/pwndbg:$(NAME)

shell: image
	docker run --rm --init --privileged --entrypoint /bin/bash -it pwndbg/pwndbg:$(NAME)

image: $(ARCHIVE)
	docker build -t pwndbg/pwndbg:$(NAME) .

$(ARCHIVE): FORCE
	rm -f $@
	cd $(ROOT) && git archive $(TREE) -o $@

FORCE:
.PHONY: all image
