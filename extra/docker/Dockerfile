FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN sed -i 's|# deb-src|deb-src|' /etc/apt/sources.list
RUN apt-get update
RUN apt-get install -y git gdb gdbserver sudo locales

RUN locale

RUN sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen
RUN locale-gen

ENV LC_ALL en_US.UTF-8 
ENV LANG en_US.UTF-8  
ENV LANGUAGE en_US:en     
ENV PYTHONIOENCODING UTF-8

RUN apt-get -y install tzdata
RUN dpkg-reconfigure --frontend noninteractive tzdata

RUN apt-get build-dep -y gdb

RUN apt-get install -y wget
COPY gdb-build.sh /root
RUN bash /root/gdb-build.sh

RUN useradd -m pwndbg
RUN passwd --delete --unlock pwndbg
RUN chsh -s $(which zsh) pwndbg
RUN echo "pwndbg ALL=(ALL:ALL) NOPASSWD: ALL" >> /etc/sudoers.d/pwntools
USER pwndbg
WORKDIR /home/pwndbg

RUN git clone https://github.com/pwndbg/pwndbg
RUN cd pwndbg && ./setup.sh
