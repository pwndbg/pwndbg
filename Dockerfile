# This dockerfile was created for development & testing purposes
#
# Build as:             docker build -t pwndbg .
#
# For testing use:      docker run --rm -it --cap-add=SYS_PTRACE pwndbg bash
#
# For development, mount the directory so the host changes are reflected into container:
#   docker run -it --cap-add=SYS_PTRACE -v `pwd`:/pwndbg pwndbg bash
#
FROM ubuntu:20.04

WORKDIR /pwndbg

ENV LANG en_US.utf8
ENV TZ=America/New_York
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone && \
    apt-get update && \
    apt-get install -y locales && \
    rm -rf /var/lib/apt/lists/* && \
    localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8 && \
    apt-get update && \
    apt-get install -y vim

ADD ./setup.sh /pwndbg/
ADD ./requirements.txt /pwndbg/
# The `git submodule` is commented because it refreshes all the sub-modules in the project
# but at this time we only need the essentials for the set up. It will execute at the end.
RUN sed -i "s/^git submodule/#git submodule/" ./setup.sh && \
    DEBIAN_FRONTEND=noninteractive ./setup.sh

# Comment these lines if you won't run the tests.
ADD ./setup-test-tools.sh /pwndbg/
RUN ./setup-test-tools.sh

RUN echo "source /pwndbg/gdbinit.py" >> ~/.gdbinit.py && \
    echo "PYTHON_MINOR=$(python3 -c "import sys;print(sys.version_info.minor)")" >> /root/.bashrc && \
    echo "PYTHON_PATH=\"/usr/local/lib/python3.${PYTHON_MINOR}/dist-packages/bin\"" >> /root/.bashrc && \
    echo "export PATH=$PATH:$PYTHON_PATH" >> /root/.bashrc

ADD . /pwndbg/

RUN git submodule update --init --recursive
