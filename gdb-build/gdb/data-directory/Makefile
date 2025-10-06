# Copyright (C) 2010-2025 Free Software Foundation, Inc.

# Makefile for building a staged copy of the data-directory.
# This file is part of GDB.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Please keep lists in this file sorted alphabetically, with one item per line.
# See gdb/Makefile.in for guidelines on ordering files and directories.

srcdir = ../../../binutils-gdb/gdb/data-directory
SYSCALLS_SRCDIR = $(srcdir)/../syscalls
PYTHON_SRCDIR = $(srcdir)/../python/lib
GUILE_SRCDIR = $(srcdir)/../guile/lib
SYSTEM_GDBINIT_SRCDIR = $(srcdir)/../system-gdbinit
VPATH = $(srcdir):$(SYSCALLS_SRCDIR):$(PYTHON_SRCDIR):$(GUILE_SRCDIR):$(SYSTEM_GDBINIT_SRCDIR)
XSLTPROC = missing

top_srcdir = ../../../binutils-gdb/gdb
top_builddir = ..

prefix = /usr/local
exec_prefix = ${prefix}

datarootdir = ${prefix}/share
datadir = ${datarootdir}

include $(srcdir)/../silent-rules.mk

SHELL = /bin/bash

LN_S = ln -s

INSTALL = /usr/bin/install -c
INSTALL_DATA = /usr/bin/install -c -m 644
INSTALL_DIR = $(SHELL) $(srcdir)/../../install-sh -d

GDB_DATADIR = ${datarootdir}/gdb

SYSCALLS_DIR = syscalls
SYSCALLS_INSTALL_DIR = $(DESTDIR)$(GDB_DATADIR)/$(SYSCALLS_DIR)
GEN_SYSCALLS_FILES = \
	aarch64-linux.xml \
	amd64-linux.xml \
	arm-linux.xml \
	i386-linux.xml \
	loongarch-linux.xml \
	mips-n32-linux.xml \
	mips-n64-linux.xml \
	mips-o32-linux.xml \
	ppc-linux.xml \
	ppc64-linux.xml \
	riscv-linux.xml \
	s390-linux.xml \
	s390x-linux.xml \
	sparc-linux.xml \
	sparc64-linux.xml

SYSCALLS_FILES = gdb-syscalls.dtd freebsd.xml netbsd.xml $(GEN_SYSCALLS_FILES)

PYTHON_DIR = python
PYTHON_INSTALL_DIR = $(DESTDIR)$(GDB_DATADIR)/$(PYTHON_DIR)
PYTHON_FILE_LIST = \
	gdb/__init__.py \
	gdb/disassembler.py \
	gdb/FrameDecorator.py \
	gdb/FrameIterator.py \
	gdb/frames.py \
	gdb/missing_debug.py \
	gdb/missing_objfile.py \
	gdb/missing_files.py \
	gdb/printing.py \
	gdb/prompt.py \
	gdb/ptwrite.py \
	gdb/styling.py \
	gdb/types.py \
	gdb/unwinder.py \
	gdb/xmethod.py \
	gdb/command/__init__.py \
	gdb/command/explore.py \
	gdb/command/frame_filters.py \
	gdb/command/missing_files.py \
	gdb/command/pretty_printers.py \
	gdb/command/prompt.py \
	gdb/command/type_printers.py \
	gdb/command/unwinders.py \
	gdb/command/xmethods.py \
	gdb/dap/breakpoint.py \
	gdb/dap/bt.py \
	gdb/dap/completions.py \
	gdb/dap/disassemble.py \
	gdb/dap/evaluate.py \
	gdb/dap/events.py \
	gdb/dap/frames.py \
	gdb/dap/globalvars.py \
	gdb/dap/__init__.py \
	gdb/dap/io.py \
	gdb/dap/launch.py \
	gdb/dap/locations.py \
	gdb/dap/memory.py \
	gdb/dap/modules.py \
	gdb/dap/next.py \
	gdb/dap/pause.py \
	gdb/dap/scopes.py \
	gdb/dap/server.py \
	gdb/dap/sources.py \
	gdb/dap/startup.py \
	gdb/dap/state.py \
	gdb/dap/threads.py \
	gdb/dap/typecheck.py \
	gdb/dap/varref.py \
	gdb/function/__init__.py \
	gdb/function/as_string.py \
	gdb/function/caller_is.py \
	gdb/function/strfns.py \
	gdb/printer/__init__.py

PYTHON_FILES = $(PYTHON_FILE_LIST)
#PYTHON_FILES =

GUILE_DIR = guile
GUILE_INSTALL_DIR = $(DESTDIR)$(GDB_DATADIR)/$(GUILE_DIR)

GUILE_SOURCE_FILES = \
	./gdb.scm \
	gdb/boot.scm \
	gdb/experimental.scm \
	gdb/init.scm \
	gdb/iterator.scm \
	gdb/printing.scm \
	gdb/support.scm \
	gdb/types.scm

GUILE_COMPILED_FILES = \
	./gdb.go \
	gdb/experimental.go \
	gdb/iterator.go \
	gdb/printing.go \
	gdb/support.go \
	gdb/types.go

#GUILE_FILES = $(GUILE_SOURCE_FILES) $(GUILE_COMPILED_FILES)
GUILE_FILES =

GUILD = 
GUILD_TARGET_FLAG = 

# Flags passed to 'guild compile'.
# Note: We can't use -Wunbound-variable because all the variables
# defined in C aren't visible when we compile.
# Note: To work around a guile 2.0.5 issue (it can't find gdb/init.scm even if
# we pass -L <dir>) we have to compile in the directory containing gdb.scm.
# We still need to pass "-L ." so that other modules are found.
GUILD_COMPILE_FLAGS = \
	$(GUILD_TARGET_FLAG) \
	-Warity-mismatch -Wformat -Wunused-toplevel \
	-L .

SYSTEM_GDBINIT_DIR = system-gdbinit
SYSTEM_GDBINIT_INSTALL_DIR = $(DESTDIR)$(GDB_DATADIR)/$(SYSTEM_GDBINIT_DIR)
SYSTEM_GDBINIT_FILES = \
	elinos.py \
	wrs-linux.py

FLAGS_TO_PASS = \
	"prefix=$(prefix)" \
	"exec_prefix=$(exec_prefix)" \
	"infodir=$(infodir)" \
	"datarootdir=$(datarootdir)" \
	"docdir=$(docdir)" \
	"htmldir=$(htmldir)" \
	"pdfdir=$(pdfdir)" \
	"libdir=$(libdir)" \
	"mandir=$(mandir)" \
	"datadir=$(datadir)" \
	"includedir=$(includedir)" \
	"against=$(against)" \
	"DESTDIR=$(DESTDIR)" \
	"AR=$(AR)" \
	"AR_FLAGS=$(AR_FLAGS)" \
	"CC=$(CC)" \
	"CFLAGS=$(CFLAGS)" \
	"CXX=$(CXX)" \
	"CXXFLAGS=$(CXXFLAGS)" \
	"DLLTOOL=$(DLLTOOL)" \
	"LDFLAGS=$(LDFLAGS)" \
	"RANLIB=$(RANLIB)" \
	"MAKEINFO=$(MAKEINFO)" \
	"MAKEHTML=$(MAKEHTML)" \
	"MAKEHTMLFLAGS=$(MAKEHTMLFLAGS)" \
	"INSTALL=$(INSTALL)" \
	"INSTALL_PROGRAM=$(INSTALL_PROGRAM)" \
	"INSTALL_DATA=$(INSTALL_DATA)" \
	"RUNTEST=$(RUNTEST)" \
	"RUNTESTFLAGS=$(RUNTESTFLAGS)"

.PHONY: all
all: stamp-syscalls stamp-python stamp-guile stamp-system-gdbinit

%.xml: # %.xml.in apply-defaults.xsl linux-defaults.xml.in
	$(ECHO_GEN) $(XSLTPROC) -o $(SYSCALLS_SRCDIR)/$@ $(SYSCALLS_SRCDIR)/apply-defaults.xsl \
		$(SYSCALLS_SRCDIR)/$@.in

.PHONY: syscall-xml
syscall-xml: $(GEN_SYSCALLS_FILES)

.PHONY: clean-syscall-xml
# Only clean files generated XML files.
clean-syscall-xml:
	files='$(GEN_SYSCALLS_FILES)' ; \
	for file in $$files; do \
		rm -f "$(SYSCALLS_SRCDIR)/$$file"; \
	done

# For portability's sake, we need to handle systems that don't have
# symbolic links.
stamp-syscalls: Makefile $(SYSCALLS_FILES)
	$(ECHO_GEN)
	$(SILENCE) rm -rf ./$(SYSCALLS_DIR)
	$(SILENCE) mkdir ./$(SYSCALLS_DIR)
	$(SILENCE) files='$(SYSCALLS_FILES)' ; \
	for file in $$files ; do \
	  f=$(SYSCALLS_SRCDIR)/$$file ; \
	  if test -f $$f ; then \
	    $(INSTALL_DATA) $$f ./$(SYSCALLS_DIR) ; \
	  fi ; \
	done
	$(SILENCE) touch $@

.PHONY: clean-syscalls
clean-syscalls:
	rm -rf $(SYSCALLS_DIR)
	rm -f stamp-syscalls

# This target is responsible for properly installing the syscalls'
# XML files in the system.
.PHONY: install-syscalls
install-syscalls:
	$(INSTALL_DIR) $(SYSCALLS_INSTALL_DIR)
	files='$(SYSCALLS_FILES)' ; \
	for file in $$files; do \
	  f=$(SYSCALLS_SRCDIR)/$$file ; \
	  if test -f $$f ; then \
	    $(INSTALL_DATA) $$f $(SYSCALLS_INSTALL_DIR) ; \
	  fi ; \
	done

.PHONY: uninstall-syscalls
uninstall-syscalls:
	files='$(SYSCALLS_FILES)' ; \
	for file in $$files ; do \
	  slashdir=`echo "/$$file" | sed 's,/[^/]*$$,,'` ; \
	  rm -f $(SYSCALLS_INSTALL_DIR)/$$file ; \
	  while test "x$$file" != "x$$slashdir" ; do \
	    rmdir 2>/dev/null "$(SYSCALLS_INSTALL_DIR)$$slashdir" ; \
	    file="$$slashdir" ; \
	    slashdir=`echo "$$file" | sed 's,/[^/]*$$,,'` ; \
	  done \
	done

stamp-python: Makefile $(PYTHON_FILES)
	$(ECHO_GEN)
	$(SILENCE) rm -rf ./$(PYTHON_DIR)
	$(SILENCE) files='$(PYTHON_FILES)' ; \
	if test "x$$files" != x ; then \
	  for file in $$files ; do \
	    dir=`echo "$$file" | sed 's,/[^/]*$$,,'` ; \
	    $(INSTALL_DIR) ./$(PYTHON_DIR)/$$dir ; \
	    $(INSTALL_DATA) $(PYTHON_SRCDIR)/$$file ./$(PYTHON_DIR)/$$dir ; \
	  done ; \
	fi
	$(SILENCE) touch $@

.PHONY: clean-python
clean-python:
	rm -rf $(PYTHON_DIR)
	rm -f stamp-python

.PHONY: install-python
install-python:
	files='$(PYTHON_FILES)' ; \
	if test "x$$files" != x ; then \
	  for file in $$files ; do \
	    dir=`echo "$$file" | sed 's,/[^/]*$$,,'` ; \
	    $(INSTALL_DIR) $(PYTHON_INSTALL_DIR)/$$dir ; \
	    $(INSTALL_DATA) ./$(PYTHON_DIR)/$$file $(PYTHON_INSTALL_DIR)/$$dir ; \
	  done ; \
	fi

.PHONY: uninstall-python
uninstall-python:
	files='$(PYTHON_FILES)' ; \
	if test "x$$files" != x ; then \
	  for file in $$files ; do \
	    slashdir=`echo "/$$file" | sed 's,/[^/]*$$,,'` ; \
	    rm -f $(PYTHON_INSTALL_DIR)/$$file ; \
	    while test "x$$file" != "x$$slashdir" ; do \
	      rmdir 2>/dev/null "$(PYTHON_INSTALL_DIR)$$slashdir" ; \
	      file="$$slashdir" ; \
	      slashdir=`echo "$$file" | sed 's,/[^/]*$$,,'` ; \
	    done \
	  done ; \
	fi

stamp-guile: Makefile $(GUILE_SOURCE_FILES)
	$(ECHO_GEN)
	$(SILENCE) rm -rf ./$(GUILE_DIR)
	$(SILENCE) if test "x$(GUILE_FILES)" != x ; then \
	  files='$(GUILE_SOURCE_FILES)' ; \
	  for file in $$files ; do \
	    dir=`echo "$$file" | sed 's,/[^/]*$$,,'` ; \
	    $(INSTALL_DIR) ./$(GUILE_DIR)/$$dir ; \
	    $(INSTALL_DATA) $(GUILE_SRCDIR)/$$file ./$(GUILE_DIR)/$$dir ; \
	  done ; \
	  files='$(GUILE_COMPILED_FILES)' ; \
	  cd ./$(GUILE_DIR) ; \
	  for go in $$files ; do \
	    source="`echo $$go | sed 's/\.go$$/.scm/'`" ; \
	    $(SILENT_ECHO) $(GUILD) compile $(GUILD_COMPILE_FLAGS) -o "$$go" "$$source" ; \
	    $(GUILD) compile $(GUILD_COMPILE_FLAGS) -o "$$go" "$$source" || exit 1 ; \
	  done ; \
	fi
	$(SILENCE) touch $@

.PHONY: clean-guile
clean-guile:
	rm -rf $(GUILE_DIR)
	rm -f stamp-guile

.PHONY: install-guile
install-guile:
	files='$(GUILE_FILES)' ; \
	if test "x$$files" != x ; then \
	  for file in $$files ; do \
	    dir=`echo "$$file" | sed 's,/[^/]*$$,,'` ; \
	    $(INSTALL_DIR) $(GUILE_INSTALL_DIR)/$$dir ; \
	    $(INSTALL_DATA) ./$(GUILE_DIR)/$$file $(GUILE_INSTALL_DIR)/$$dir ; \
	  done ; \
	fi

.PHONY: uninstall-guile
uninstall-guile:
	files='$(GUILE_FILES)' ; \
	if test "x$$files" != x ; then \
	  for file in $$files ; do \
	    slashdir=`echo "/$$file" | sed 's,/[^/]*$$,,'` ; \
	    rm -f $(GUILE_INSTALL_DIR)/$$file ; \
	    while test "x$$file" != "x$$slashdir" ; do \
	      rmdir 2>/dev/null "$(GUILE_INSTALL_DIR)$$slashdir" ; \
	      file="$$slashdir" ; \
	      slashdir=`echo "$$file" | sed 's,/[^/]*$$,,'` ; \
	    done \
	  done ; \
	fi

stamp-system-gdbinit: Makefile $(SYSTEM_GDBINIT_FILES)
	$(ECHO_GEN)
	$(SILENCE) rm -rf ./$(SYSTEM_GDBINIT_DIR)
	$(SILENCE) mkdir ./$(SYSTEM_GDBINIT_DIR)
	$(SILENCE) files='$(SYSTEM_GDBINIT_FILES)' ; \
	for file in $$files ; do \
	  f=$(SYSTEM_GDBINIT_SRCDIR)/$$file ; \
	  if test -f $$f ; then \
	    $(INSTALL_DATA) $$f ./$(SYSTEM_GDBINIT_DIR) ; \
	  fi ; \
	done
	$(SILENCE) touch $@

.PHONY: clean-system-gdbinit
clean-system-gdbinit:
	rm -rf $(SYSTEM_GDBINIT_DIR)
	rm -f stamp-system-gdbinit

.PHONY: install-system-gdbinit
install-system-gdbinit:
	$(INSTALL_DIR) $(SYSTEM_GDBINIT_INSTALL_DIR)
	files='$(SYSTEM_GDBINIT_FILES)' ; \
	for file in $$files; do \
	  f=$(SYSTEM_GDBINIT_SRCDIR)/$$file ; \
	  if test -f $$f ; then \
	    $(INSTALL_DATA) $$f $(SYSTEM_GDBINIT_INSTALL_DIR) ; \
	  fi ; \
	done

.PHONY: uninstall-system-gdbinit
uninstall-system-gdbinit:
	files='$(SYSTEM_GDBINIT_FILES)' ; \
	for file in $$files ; do \
	  slashdir=`echo "/$$file" | sed 's,/[^/]*$$,,'` ; \
	  rm -f $(SYSTEM_GDBINIT_INSTALL_DIR)/$$file ; \
	  while test "x$$file" != "x$$slashdir" ; do \
	    rmdir 2>/dev/null "$(SYSTEM_GDBINIT_INSTALL_DIR)$$slashdir" ; \
	    file="$$slashdir" ; \
	    slashdir=`echo "$$file" | sed 's,/[^/]*$$,,'` ; \
	  done \
	done

# Traditionally "install" depends on "all".  But it may be useful
# not to; for example, if the user has made some trivial change to a
# source file and doesn't care about rebuilding or just wants to save the
# time it takes for make to check that all is up to date.
# install-only is intended to address that need.
.PHONY: install
install: all
	@$(MAKE) $(FLAGS_TO_PASS) install-only

.PHONY: install-only
install-only: install-syscalls install-python install-guile \
	install-system-gdbinit

.PHONY: uninstall
uninstall: uninstall-syscalls uninstall-python uninstall-guile \
	uninstall-system-gdbinit

.PHONY: clean
clean: clean-syscalls clean-python clean-guile clean-system-gdbinit

.PHONY: maintainer-clean realclean distclean
maintainer-clean realclean distclean: clean
	rm -f Makefile

.PHONY: check installcheck info dvi pdf html
.PHONY: install-info install-pdf install-html clean-info
check installcheck:
info dvi pdf html:
install-info install-dvi install-pdf install-html:
clean-info:

# GNU Make has an annoying habit of putting *all* the Makefile variables
# into the environment, unless you include this target as a circumvention.
# Rumor is that this will be fixed (and this target can be removed)
# in GNU Make 4.0.
.NOEXPORT:

# GNU Make 3.63 has a different problem: it keeps tacking command line
# overrides onto the definition of $(MAKE).  This variable setting
# will remove them.
MAKEOVERRIDES=

Makefile: $(srcdir)/Makefile.in $(top_builddir)/config.status
	$(ECHO_GEN) cd .. && $(SHELL) ./config.status $(SILENT_FLAG) data-directory/Makefile

# Disable implicit make rules.
include $(srcdir)/../disable-implicit-rules.mk
