NAME?=pwndbg
ROOT=$(shell git rev-parse --show-toplevel)
IMAGE=$(shell docker ps -f ancestor=zach-ctf --last 1 -q)

ifeq ($(strip $(SHA)),)
SHA = HEAD
endif


all: build

build:
	docker build -t $(NAME) .

run: build
	docker run \
		--cpus 2 \
		--ulimit core=-1 \
		--rm \
		-h ctf \
		--interactive \
		--tty \
		--privileged \
		--net=host \
		-v ${PWD}/../..:/home/pwndbg/pwndbg \
		-v ${PWD}/shared:/shared \
		-p 41414:41414 \
		$(NAME):latest \
		$(COMMAND)

.PHONY: all build run
