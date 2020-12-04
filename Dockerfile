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

ENV TZ=America/New_York
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone && \
    apt-get update && \
    apt-get -y install vim golang

ADD . /pwndbg/

RUN cd /pwndbg && \
    DEBIAN_FRONTEND=noninteractive ./setup.sh

RUN echo "source /pwndbg/gdbinit.py" >> ~/.gdbinit.py && \
    echo "PYTHON_MINOR=$(python3 -c "import sys;print(sys.version_info.minor)")" >> /root/.bashrc && \
    echo "PYTHON_PATH=\"/usr/local/lib/python3.${PYTHON_MINOR}/dist-packages/bin\"" >> /root/.bashrc && \
    echo "export PATH=$PATH:$PYTHON_PATH" >> /root/.bashrc && \
    cat ~/.gdbinit.py | grep -i source && \
    cat /root/.bashrc | grep -i python
