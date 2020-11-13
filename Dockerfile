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

ADD . /pwndbg/
RUN cd /pwndbg && DEBIAN_FRONTEND=noninteractive ./setup.sh
RUN echo 'source /pwndbg/gdbinit.py' >> ~/.gdbinit.py

# Python3 path exporting
RUN echo 'PYTHON_MINOR=$(python3 -c "import sys;print(sys.version_info.minor)")' >> /root/.bashrc
RUN echo 'PYTHON_PATH="/usr/local/lib/python3.${PYTHON_MINOR}/dist-packages/bin"' >> /root/.bashrc
RUN echo 'export PATH=$PATH:$PYTHON_PATH' >> /root/.bashrc
