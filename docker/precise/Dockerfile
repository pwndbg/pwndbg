FROM ubuntu:precise

RUN apt-get update
RUN apt-get install -y git sudo
WORKDIR /root
RUN git clone https://github.com/pwndbg/pwndbg
COPY pwndbg.tar.gz .
RUN tar -C pwndbg -xf pwndbg.tar.gz
WORKDIR pwndbg
RUN bash -ex setup.sh

