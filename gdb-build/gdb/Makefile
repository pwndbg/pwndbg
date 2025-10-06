# Copyright (C) 1989-2025 Free Software Foundation, Inc.

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
# Here are the general guidelines for ordering files and directories:
#
#   - Files come before directories.
#   - The extensions are not taken into account when comparing filenames, except
#     if the filenames are otherwise equal.
#   - A filename that is a prefix of another one comes before.
#   - Underscores and dashes are treated equally, and come before alphanumeric
#     characters.
#
# For example:
#
# SOME_FILES = \
# 	foo.c \
# 	foo.h \
# 	foo-bar.c \
# 	foobar.c \
# 	foo/bar.c

prefix = /usr/local
exec_prefix = ${prefix}

host_alias = x86_64-pc-linux-gnu
target_alias = x86_64-pc-linux-gnu
program_transform_name = s,y,y,
bindir = ${exec_prefix}/bin
libdir = ${exec_prefix}/lib
tooldir = $(libdir)/$(target_alias)

datadir = ${datarootdir}
localedir = ${datadir}/locale
mandir = ${datarootdir}/man
man1dir = $(mandir)/man1
man2dir = $(mandir)/man2
man3dir = $(mandir)/man3
man4dir = $(mandir)/man4
man5dir = $(mandir)/man5
man6dir = $(mandir)/man6
man7dir = $(mandir)/man7
man8dir = $(mandir)/man8
man9dir = $(mandir)/man9
infodir = ${datarootdir}/info
datarootdir = ${prefix}/share
docdir = ${datarootdir}/doc/${PACKAGE}
htmldir = ${docdir}
pdfdir = ${docdir}
includedir = ${prefix}/include

install_sh = ${SHELL} /home/hussain/GitHub/pwndbg/binutils-gdb/install-sh

# This can be referenced by `LIBINTL' as computed by
# ZW_GNU_GETTEXT_SISTER_DIR.
top_builddir = .

SHELL = /bin/bash
EXEEXT = 

AWK = gawk
LN_S = ln -s

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = /usr/bin/install -c
INSTALL_SCRIPT = /usr/bin/install -c
INSTALL_STRIP_PROGRAM = $(install_sh) -c -s
INSTALL_DATA = /usr/bin/install -c -m 644

DESTDIR =

AR = ar --plugin /usr/libexec/gcc/x86_64-linux-gnu/13/liblto_plugin.so
AR_FLAGS = qv
RANLIB = ranlib --plugin /usr/libexec/gcc/x86_64-linux-gnu/13/liblto_plugin.so
DLLTOOL = dlltool
WINDRES = windres
MIG = 
STRIP = strip

XGETTEXT = :
GMSGFMT = :
MSGMERGE = msgmerge

PACKAGE = gdb
CATALOGS = 

CC = gcc
CXX = g++
CXX_DIALECT = 

# Dependency tracking information.
DEPMODE = depmode=gcc3
DEPDIR = .deps
depcomp = $(SHELL) $(srcdir)/../depcomp

# Directory containing source files.
srcdir = ../../binutils-gdb/gdb
VPATH = ../../binutils-gdb/gdb
top_srcdir = ../../binutils-gdb/gdb

include $(srcdir)/silent-rules.mk

# Note that these are overridden by GNU make-specific code below if
# GNU make is used.  The overrides implement dependency tracking.
COMPILE.pre = $(CXX) -x c++ $(CXX_DIALECT)
COMPILE.post = -c -o $@
POSTCOMPILE = @true

# CXXFLAGS is at the very end on purpose, so that user-supplied flags can
# override internal flags.
COMPILE = $(ECHO_CXX) $(COMPILE.pre) $(INTERNAL_CFLAGS) $(CXXFLAGS) \
	$(COMPILE.post)

YACC = /home/hussain/GitHub/pwndbg/binutils-gdb/missing bison -y

# This is used to rebuild ada-lex.c from ada-lex.l.  If the program is
# not defined, but ada-lex.c is present, compilation will continue,
# possibly with a warning.
FLEX = flex

YLWRAP = $(srcdir)/../ylwrap

# where to find makeinfo, preferably one designed for texinfo-2
MAKEINFO = makeinfo --split-size=5000000
MAKEINFOFLAGS = 
MAKEINFO_EXTRA_FLAGS =  -DHAVE_MAKEINFO_CLICK
MAKEINFO_CMD = $(MAKEINFO) $(MAKEINFOFLAGS) $(MAKEINFO_EXTRA_FLAGS)

MAKEHTML = $(MAKEINFO_CMD) --html
MAKEHTMLFLAGS =

LIBTOOL = $(SHELL) $(top_builddir)/libtool

# Set this up with gcc if you have gnu ld and the loader will print out
# line numbers for undefined references.
#CC_LD = g++ -static
CC_LD = $(LIBTOOL) $(SILENT_FLAG) --mode=link $(CXX) $(CXX_DIALECT)

# Where is our "include" directory?  Typically $(srcdir)/../include.
# This is essentially the header file directory for the library
# routines in libiberty.
INCLUDE_DIR = $(srcdir)/../include
INCLUDE_CFLAGS = -I$(INCLUDE_DIR)

# Where is the "-liberty" library?  Typically in ../libiberty.
LIBIBERTY = ../libiberty/libiberty.a

# Where is the CTF library?  Typically in ../libctf.
LIBCTF = ../libctf/libctf.la
CTF_DEPS = ../libctf/libctf.la

# Where is the BFD library?  Typically in ../bfd.
BFD_DIR = ../bfd
BFD = $(BFD_DIR)/libbfd.la
BFD_SRC = $(srcdir)/$(BFD_DIR)
BFD_CFLAGS = -I$(BFD_DIR) -I$(BFD_SRC)

# This is where we get zlib from.  zlibdir is -L../zlib and zlibinc is
# -I../zlib, unless we were configured with --with-system-zlib, in which
# case both are empty.
ZLIB = -L$(top_builddir)/../zlib -lz
ZLIBINC = -I$(top_srcdir)/../zlib

ZSTD_CFLAGS = 
ZSTD_LIBS = -lzstd 

# Where is the decnumber library?  Typically in ../libdecnumber.
LIBDECNUMBER_DIR = ../libdecnumber
LIBDECNUMBER = $(LIBDECNUMBER_DIR)/libdecnumber.a
LIBDECNUMBER_SRC = $(srcdir)/$(LIBDECNUMBER_DIR)
LIBDECNUMBER_CFLAGS = -I$(LIBDECNUMBER_DIR) -I$(LIBDECNUMBER_SRC)

# Where is the READLINE library?  Typically in ../readline/readline.
READLINE_DIR = ../readline/readline
READLINE_SRC = $(srcdir)/$(READLINE_DIR)
READLINE = -lreadline
READLINE_DEPS = 
READLINE_CFLAGS = 

# Where is expat?  This will be empty if expat was not available.
LIBEXPAT = -lexpat

# Where is lzma?  This will be empty if lzma was not available.
LIBLZMA = -llzma

# Where is libbabeltrace? This will be empty if libbabeltrace was not
# available.
LIBBABELTRACE = 

# Where is libxxhash? This will be empty if libxxhash was not
# available.
LIBXXHASH = 

# Where is libipt?  This will be empty if libipt was not available.
LIBIPT = 

# How to find GMP and MPFR
GMPLIBS = -lmpfr -lgmp
GMPINC = 

# GNU source highlight library.
SRCHIGH_LIBS = 
SRCHIGH_CFLAGS = 

WARN_CFLAGS =  -Wall -Wdeprecated-copy -Wdeprecated-copy-dtor -Wduplicated-cond -Wempty-body -Wimplicit-fallthrough=5 -Wmissing-declarations -Wno-char-subscripts -Wno-mismatched-tags -Wno-sign-compare -Wno-error=maybe-uninitialized -Wno-switch -Wno-unused -Wpointer-arith -Wredundant-move -Wshadow=local -Wstrict-null-sentinel -Wsuggest-override -Wunused-but-set-parameter -Wunused-but-set-variable -Wunused-const-variable=1 -Wunused-function -Wunused-label -Wunused-local-typedefs -Wunused-value -Wunused-variable -Wvla -Wformat -Wformat-nonliteral
WERROR_CFLAGS = 
GDB_WARN_CFLAGS = $(WARN_CFLAGS)
GDB_WERROR_CFLAGS = $(WERROR_CFLAGS)

PTHREAD_CFLAGS = -pthread
PTHREAD_LIBS = 

DEBUGINFOD_CFLAGS = 
DEBUGINFOD_LIBS = 

AMD_DBGAPI_CFLAGS = 
AMD_DBGAPI_LIBS = 

RDYNAMIC = -Wl,--dynamic-list=$(srcdir)/proc-service.list

# Where is the INTL library?  Typically in ../intl.
INTL = 
INTL_DEPS = 
INTL_CFLAGS = 

# Where is the ICONV library?  This will be empty if in libc or not available.
LIBICONV = 

# Did the user give us a --with-gdb-datadir option?
GDB_DATADIR = ${datarootdir}/gdb

# Code signing.
CODESIGN = codesign
CODESIGN_CERT = 

# Flags to pass to gdb when invoked with "make run".
GDBFLAGS =

# Helper code from gnulib.
GNULIB_PARENT_DIR = ..
include $(GNULIB_PARENT_DIR)/gnulib/Makefile.gnulib.inc

# For libbacktrace.
LIBBACKTRACE_INC=-I../../binutils-gdb/gdb/../libbacktrace/ -I../libbacktrace/
LIBBACKTRACE_LIB=../libbacktrace/libbacktrace.la

SUPPORT = ../gdbsupport
LIBSUPPORT = $(SUPPORT)/libgdbsupport.a
INCSUPPORT = \
	-I$(srcdir)/.. \
	-I..

#
# CLI sub directory definitions
#
SUBDIR_CLI_SRCS = \
	cli/cli-cmds.c \
	cli/cli-decode.c \
	cli/cli-dump.c \
	cli/cli-interp.c \
	cli/cli-logging.c \
	cli/cli-option.c \
	cli/cli-script.c \
	cli/cli-setshow.c \
	cli/cli-style.c \
	cli/cli-utils.c

SUBDIR_CLI_OBS = $(patsubst %.c,%.o,$(SUBDIR_CLI_SRCS))

#
# MI sub directory definitions
#
SUBDIR_MI_SRCS = \
	mi/mi-cmd-break.c \
	mi/mi-cmd-catch.c \
	mi/mi-cmd-disas.c \
	mi/mi-cmd-env.c \
	mi/mi-cmd-file.c \
	mi/mi-cmd-info.c \
	mi/mi-cmd-stack.c \
	mi/mi-cmd-target.c \
	mi/mi-cmd-var.c \
	mi/mi-cmds.c \
	mi/mi-common.c \
	mi/mi-console.c \
	mi/mi-getopt.c \
	mi/mi-interp.c \
	mi/mi-main.c \
	mi/mi-out.c \
	mi/mi-parse.c \
	mi/mi-symbol-cmds.c

SUBDIR_MI_OBS = $(patsubst %.c,%.o,$(SUBDIR_MI_SRCS))

#
# TUI sub directory definitions
#
SUBDIR_TUI_SRCS = \
	tui/tui.c \
	tui/tui-command.c \
	tui/tui-data.c \
	tui/tui-disasm.c \
	tui/tui-file.c \
	tui/tui-hooks.c \
	tui/tui-interp.c \
	tui/tui-io.c \
	tui/tui-layout.c \
	tui/tui-location.c \
	tui/tui-regs.c \
	tui/tui-source.c \
	tui/tui-status.c \
	tui/tui-win.c \
	tui/tui-wingeneral.c \
	tui/tui-winsource.c

SUBDIR_TUI_OBS = $(patsubst %.c,%.o,$(SUBDIR_TUI_SRCS))

SUBDIR_TUI_DEPS =
SUBDIR_TUI_LDFLAGS =
SUBDIR_TUI_CFLAGS = -DTUI=1

#
# GCC Compile support sub-directory definitions
#
SUBDIR_GCC_COMPILE_SRCS = \
	compile/compile.c \
	compile/compile-c-support.c \
	compile/compile-c-symbols.c \
	compile/compile-c-types.c \
	compile/compile-cplus-symbols.c \
	compile/compile-cplus-types.c \
	compile/compile-loc2c.c \
	compile/compile-object-load.c \
	compile/compile-object-run.c

SUBDIR_GCC_COMPILE_OBS = $(patsubst %.c,%.o,$(filter %.c,$(SUBDIR_GCC_COMPILE_SRCS)))

#
# Guile sub directory definitions for guile support.
#
SUBDIR_GUILE_SRCS = \
	guile/guile.c \
	guile/scm-arch.c \
	guile/scm-auto-load.c \
	guile/scm-block.c \
	guile/scm-breakpoint.c \
	guile/scm-cmd.c \
	guile/scm-color.c \
	guile/scm-disasm.c \
	guile/scm-exception.c \
	guile/scm-frame.c \
	guile/scm-gsmob.c \
	guile/scm-iterator.c \
	guile/scm-lazy-string.c \
	guile/scm-math.c \
	guile/scm-objfile.c \
	guile/scm-param.c \
	guile/scm-ports.c \
	guile/scm-pretty-print.c \
	guile/scm-progspace.c \
	guile/scm-safe-call.c \
	guile/scm-string.c \
	guile/scm-symbol.c \
	guile/scm-symtab.c \
	guile/scm-type.c \
	guile/scm-utils.c \
	guile/scm-value.c

SUBDIR_GUILE_OBS = $(patsubst %.c,%.o,$(SUBDIR_GUILE_SRCS))

SUBDIR_GUILE_DEPS =
SUBDIR_GUILE_LDFLAGS =
SUBDIR_GUILE_CFLAGS =

#
# python sub directory definitions
#
SUBDIR_PYTHON_SRCS = \
	python/py-arch.c \
	python/py-auto-load.c \
	python/py-block.c \
	python/py-bpevent.c \
	python/py-breakpoint.c \
	python/py-cmd.c \
	python/py-color.c \
	python/py-connection.c \
	python/py-continueevent.c \
	python/py-dap.c \
	python/py-disasm.c \
	python/py-event.c \
	python/py-evtregistry.c \
	python/py-evts.c \
	python/py-exitedevent.c \
	python/py-finishbreakpoint.c \
	python/py-frame.c \
	python/py-framefilter.c \
	python/py-function.c \
	python/py-gdb-readline.c \
	python/py-inferior.c \
	python/py-infevents.c \
	python/py-infthread.c \
	python/py-instruction.c \
	python/py-lazy-string.c \
	python/py-linetable.c \
	python/py-membuf.c \
	python/py-mi.c \
	python/py-micmd.c \
	python/py-newobjfileevent.c \
	python/py-objfile.c \
	python/py-param.c \
	python/py-prettyprint.c \
	python/py-progspace.c \
	python/py-record.c \
	python/py-record-btrace.c \
	python/py-record-full.c \
	python/py-registers.c \
	python/py-signalevent.c \
	python/py-stopevent.c \
	python/py-symbol.c \
	python/py-symtab.c \
	python/py-threadevent.c \
	python/py-tui.c \
	python/py-type.c \
	python/py-unwind.c \
	python/py-utils.c \
	python/py-value.c \
	python/py-varobj.c \
	python/py-xmethods.c \
	python/python.c

SUBDIR_PYTHON_OBS = $(patsubst %.c,%.o,$(SUBDIR_PYTHON_SRCS))

SUBDIR_PYTHON_DEPS =
SUBDIR_PYTHON_LDFLAGS =
SUBDIR_PYTHON_CFLAGS =

SELFTESTS_SRCS = \
	disasm-selftests.c \
	gdbarch-selftests.c \
	selftest-arch.c \
	unittests/array-view-selftests.c \
	unittests/child-path-selftests.c \
	unittests/cli-utils-selftests.c \
	unittests/command-def-selftests.c \
	unittests/common-utils-selftests.c \
	unittests/copy_bitwise-selftests.c \
	unittests/enum-flags-selftests.c \
	unittests/environ-selftests.c \
	unittests/filtered_iterator-selftests.c \
	unittests/format_pieces-selftests.c \
	unittests/frame_info_ptr-selftests.c \
	unittests/function-view-selftests.c \
	unittests/gdb_tilde_expand-selftests.c \
	unittests/gmp-utils-selftests.c \
	unittests/intrusive_list-selftests.c \
	unittests/lookup_name_info-selftests.c \
	unittests/memory-map-selftests.c \
	unittests/memrange-selftests.c \
	unittests/offset-type-selftests.c \
	unittests/observable-selftests.c \
	unittests/packed-selftests.c \
	unittests/parallel-for-selftests.c \
	unittests/parse-connection-spec-selftests.c \
	unittests/path-join-selftests.c \
	unittests/ptid-selftests.c \
	unittests/main-thread-selftests.c \
	unittests/mkdir-recursive-selftests.c \
	unittests/remote-arg-selftests.c \
	unittests/rsp-low-selftests.c \
	unittests/scoped_fd-selftests.c \
	unittests/scoped_ignore_signal-selftests.c \
	unittests/scoped_mmap-selftests.c \
	unittests/scoped_restore-selftests.c \
	unittests/search-memory-selftests.c \
	unittests/style-selftests.c \
	unittests/tracepoint-selftests.c \
	unittests/tui-selftests.c \
	unittests/ui-file-selftests.c \
	unittests/unique_xmalloc_ptr_char.c \
	unittests/unpack-selftests.c \
	unittests/vec-utils-selftests.c \
	unittests/xml-utils-selftests.c

SELFTESTS_OBS = $(patsubst %.c,%.o,$(SELFTESTS_SRCS))

SUBDIR_TARGET_SRCS = target/target.c target/waitstatus.c
SUBDIR_TARGET_OBS = $(patsubst %.c,%.o,$(SUBDIR_TARGET_SRCS))


# Opcodes currently live in one of two places.  Either they are in the
# opcode library, typically ../opcodes, or they are in a header file
# in INCLUDE_DIR.
# Where is the "-lopcodes" library, with (some of) the opcode tables and
# disassemblers?
OPCODES_DIR = ../opcodes
OPCODES_SRC = $(srcdir)/$(OPCODES_DIR)
OPCODES = $(OPCODES_DIR)/libopcodes.la
# Where are the other opcode tables which only have header file
# versions?
OP_INCLUDE = $(INCLUDE_DIR)/opcode
# See TOP_CFLAGS as well.
OPCODES_CFLAGS = -I$(OP_INCLUDE)

# Allow includes like "opcodes/mumble.h".
TOP_CFLAGS = -I$(top_srcdir)/..

# The simulator is usually nonexistent; targets that include one
# should set this to list all the .o or .a files to be linked in.
SIM = 

WIN32LIBS =  

# Tcl et al cflags and libraries
TCL = 
TCL_CFLAGS = 
GDBTKLIBS = 
# Extra flags that the GDBTK files need:
GDBTK_CFLAGS = 

TK = 
TK_CFLAGS = 

X11_CFLAGS = 
X11_LDFLAGS =
X11_LIBS =

WIN32LDAPP = 

LIBGUI = ../libgui/src/libgui.a
GUI_CFLAGS_X = -I../../binutils-gdb/gdb/../libgui/src
IDE_CFLAGS = $(GUI_CFLAGS_X) $(IDE_CFLAGS_X)

ALL_TCL_CFLAGS = $(TCL_CFLAGS) $(TK_CFLAGS)

# The version of gdbtk we're building. This should be kept
# in sync with GDBTK_VERSION and friends in gdbtk.h.
GDBTK_VERSION = 1.0
GDBTK_LIBRARY = $(datadir)/insight$(GDBTK_VERSION)

# Gdbtk requires an absolute path to the source directory or
# the testsuite won't run properly.
GDBTK_SRC_DIR = 

SUBDIR_GDBTK_OBS = \
	gdbtk.o \
	gdbtk-bp.o \
	gdbtk-cmds.o \
	gdbtk-hooks.o \
	gdbtk-interp.o \
	gdbtk-register.o \
	gdbtk-stack.o \
	gdbtk-varobj.o \
	gdbtk-wrapper.o

SUBDIR_GDBTK_SRCS = \
	gdbtk/generic/gdbtk.c \
	gdbtk/generic/gdbtk-bp.c \
	gdbtk/generic/gdbtk-cmds.c \
	gdbtk/generic/gdbtk-hooks.c \
	gdbtk/generic/gdbtk-interp.c \
	gdbtk/generic/gdbtk-main.c \
	gdbtk/generic/gdbtk-register.c \
	gdbtk/generic/gdbtk-stack.c \
	gdbtk/generic/gdbtk-varobj.c \
	gdbtk/generic/gdbtk-wrapper.c

SUBDIR_GDBTK_DEPS = $(LIBGUI) $(TCL_DEPS) $(TK_DEPS)
SUBDIR_GDBTK_LDFLAGS =
SUBDIR_GDBTK_CFLAGS = -DGDBTK

CONFIG_OBS =  mdebugread.o $(DWARF2_OBS) $(SUBDIR_TUI_OBS) $(SUBDIR_PYTHON_OBS) guile/guile.o $(SUBDIR_GCC_COMPILE_OBS) gcore-elf.o elf-none-tdep.o posix-hdep.o $(SELFTESTS_OBS)
CONFIG_SRCS =  mdebugread.c $(DWARF2_SRCS) $(SUBDIR_TUI_SRCS) $(SUBDIR_PYTHON_SRCS) guile/guile.c $(SELFTESTS_SRCS)
CONFIG_DEPS =  $(SUBDIR_TUI_DEPS) $(SUBDIR_PYTHON_DEPS)
CONFIG_LDFLAGS = 
ENABLE_CFLAGS =  $(SUBDIR_TUI_CFLAGS) $(SUBDIR_PYTHON_CFLAGS)
CONFIG_ALL = 
CONFIG_CLEAN = 
CONFIG_INSTALL =  install-python
CONFIG_UNINSTALL = 
HAVE_NATIVE_GCORE_TARGET = 1
HAVE_GSTACK = 1

CONFIG_SRC_SUBDIR = arch cli dwarf2 mi compile tui unittests guile python \
	target nat
CONFIG_DEP_SUBDIR = $(addsuffix /$(DEPDIR),$(CONFIG_SRC_SUBDIR))

# -I. for config files.
# -I$(srcdir) for gdb internal headers.
# -I$(srcdir)/config for more generic config files.

# It is also possible that you will need to add -I/usr/include/sys if
# your system doesn't have fcntl.h in /usr/include (which is where it
# should be according to Posix).
DEFS = -DHAVE_CONFIG_H
GDB_INCLUDED_HEADER = -include $(srcdir)/defs.h
GDB_CFLAGS = \
	-I. \
	-I$(srcdir) \
	-I$(srcdir)/config \
	$(GDB_INCLUDED_HEADER) \
	-DLOCALEDIR="\"$(localedir)\"" \
	$(DEFS)

# MH_CFLAGS, if defined, has host-dependent CFLAGS from the config directory.
GLOBAL_CFLAGS = $(MH_CFLAGS)

PROFILE_CFLAGS = 

# These are specifically reserved for setting from the command line
# when running make.  I.E.: "make CFLAGS=-Wmissing-prototypes".
CFLAGS = -g -O2    
CXXFLAGS = -g -O2    
CPPFLAGS = 

# Set by configure, for e.g. expat.  Python installations are such that
# C headers are included using their basename (for example, we #include
# <Python.h> rather than, say, <python/Python.h>).  Since the file names
# are sometimes a little generic, we think that the risk of collision
# with other header files is high.  If that happens, we try to mitigate
# a bit the consequences by putting the Python includes last in the list.
INTERNAL_CPPFLAGS = $(CPPFLAGS)  -I/usr/include/python3.12 -I/usr/include/python3.12 \
	

# INTERNAL_CFLAGS is the aggregate of all other *CFLAGS macros.
INTERNAL_CFLAGS = \
	$(GLOBAL_CFLAGS) \
	$(PROFILE_CFLAGS) \
	$(GDB_CFLAGS) \
	$(OPCODES_CFLAGS) \
	$(BFD_CFLAGS) \
	$(INCLUDE_CFLAGS) \
	$(READLINE_CFLAGS) \
	$(ZLIBINC) \
	$(ZSTD_CFLAGS) \
	$(LIBDECNUMBER_CFLAGS) \
	$(INTL_CFLAGS) \
	$(INCGNU) \
	$(INCSUPPORT) \
	$(LIBBACKTRACE_INC) \
	$(ENABLE_CFLAGS) \
	$(INTERNAL_CPPFLAGS) \
	$(SRCHIGH_CFLAGS) \
	$(TOP_CFLAGS) \
	$(PTHREAD_CFLAGS) \
	$(DEBUGINFOD_CFLAGS) \
	$(GMPINC) \
	$(AMD_DBGAPI_CFLAGS) \
	$(GDB_WARN_CFLAGS) \
	$(GDB_WERROR_CFLAGS)

# LDFLAGS is specifically reserved for setting from the command line
# when running make.
LDFLAGS =  

# Profiling options need to go here to work.
# I think it's perfectly reasonable for a user to set -pg in CFLAGS
# and have it work; that's why CFLAGS is here.
# PROFILE_CFLAGS is _not_ included, however, because we use monstartup.
INTERNAL_LDFLAGS = \
	$(CXXFLAGS) $(GLOBAL_CFLAGS) $(MH_LDFLAGS) \
	$(LDFLAGS) $(CONFIG_LDFLAGS) $(PTHREAD_CFLAGS)

# Libraries and corresponding dependencies for compiling gdb.
# XM_CLIBS, defined in *config files, have host-dependent libs.
# LIBIBERTY appears twice on purpose.
CLIBS = $(SIM) $(READLINE) $(OPCODES) $(LIBCTF) $(BFD) $(ZLIB) $(ZSTD_LIBS) \
        $(LIBSUPPORT) $(INTL) $(LIBIBERTY) $(LIBDECNUMBER) \
	$(XM_CLIBS) $(GDBTKLIBS)  $(LIBBACKTRACE_LIB) \
	-lncursesw -lm   -lpython3.12 -ldl -lm  -Wl,-O1 -Wl,-Bsymbolic-functions $(AMD_DBGAPI_LIBS) \
	$(LIBEXPAT) $(LIBLZMA) $(LIBBABELTRACE) $(LIBIPT) \
	$(WIN32LIBS) $(LIBGNU) $(LIBGNU_EXTRA_LIBS) $(LIBICONV) \
	$(GMPLIBS) $(SRCHIGH_LIBS) $(LIBXXHASH) $(PTHREAD_LIBS) \
	$(DEBUGINFOD_LIBS) $(LIBBABELTRACE_LIB)
CDEPS = $(NAT_CDEPS) $(SIM) $(BFD) $(READLINE_DEPS) $(CTF_DEPS) \
	$(OPCODES) $(INTL_DEPS) $(LIBIBERTY) $(CONFIG_DEPS) $(LIBGNU) \
	$(LIBSUPPORT)

DIST = gdb

RUNTEST = runtest
RUNTESTFLAGS =

# XML files to build in to GDB.
XMLFILES = \
	$(srcdir)/features/btrace.dtd \
	$(srcdir)/features/btrace-conf.dtd \
	$(srcdir)/features/gdb-target.dtd \
	$(srcdir)/features/library-list.dtd \
	$(srcdir)/features/library-list-aix.dtd \
	$(srcdir)/features/library-list-svr4.dtd \
	$(srcdir)/features/osdata.dtd \
	$(srcdir)/features/threads.dtd \
	$(srcdir)/features/traceframe-info.dtd \
	$(srcdir)/features/xinclude.dtd

# Build the ser-*.o files the host supports.  This includes ser-unix.o
# for any system that supports a POSIX interface to the serial port.
# See configure.ac.
SER_HARDWIRE = ser-base.o ser-unix.o ser-pipe.o ser-tcp.o ser-uds.o

# This is remote-sim.o if a simulator is to be linked in.
SIM_OBS = 

# Target-dependent object files.
TARGET_OBS = $(ALL_TARGET_OBS) $(ALL_64_TARGET_OBS)

# All target-dependent object files that require the amd-dbgapi
# target to be available (used with --enable-targets=all).
ALL_AMD_DBGAPI_TARGET_OBS = \
	amdgpu-tdep.o \
	solib-rocm.o

# All target-dependent objects files that require 64-bit CORE_ADDR
# (used with --enable-targets=all --enable-64-bit-bfd).
ALL_64_TARGET_OBS = \
	aarch64-fbsd-tdep.o \
	aarch64-linux-tdep.o \
	aarch64-newlib-tdep.o \
	aarch64-ravenscar-thread.o \
	aarch64-tdep.o \
	alpha-bsd-tdep.o \
	alpha-linux-tdep.o \
	alpha-mdebug-tdep.o \
	alpha-netbsd-tdep.o \
	alpha-obsd-tdep.o \
	alpha-tdep.o \
	amd64-darwin-tdep.o \
	amd64-dicos-tdep.o \
	amd64-fbsd-tdep.o \
	amd64-gnu-tdep.o \
	amd64-linux-tdep.o \
	amd64-netbsd-tdep.o \
	amd64-obsd-tdep.o \
	amd64-ravenscar-thread.o \
	amd64-sol2-tdep.o \
	amd64-tdep.o \
	amd64-windows-tdep.o \
	arch/aarch64.o \
	arch/aarch64-insn.o \
	arch/aarch64-mte.o \
	arch/aarch64-mte-linux.o \
	arch/aarch64-scalable-linux.o \
	arch/amd64-linux-tdesc.o \
	arch/amd64.o \
	arch/riscv.o \
	bpf-tdep.o \
	ia64-linux-tdep.o \
	ia64-tdep.o \
	ia64-vms-tdep.o \
	loongarch-linux-tdep.o \
	loongarch-tdep.o \
	mips-fbsd-tdep.o \
	mips-linux-tdep.o \
	mips-netbsd-tdep.o \
	mips-sde-tdep.o \
	mips-tdep.o \
	mips64-obsd-tdep.o \
	riscv-linux-canonicalize-syscall-gen.o \
	riscv-fbsd-tdep.o \
	riscv-linux-tdep.o \
	riscv-none-tdep.o \
	riscv-ravenscar-thread.o \
	riscv-tdep.o \
	sparc64-fbsd-tdep.o \
	sparc64-linux-tdep.o \
	sparc64-netbsd-tdep.o \
	sparc64-obsd-tdep.o \
	sparc64-sol2-tdep.o \
	sparc64-tdep.o \
	tilegx-linux-tdep.o \
	tilegx-tdep.o


# All other target-dependent objects files (used with --enable-targets=all).
ALL_TARGET_OBS = \
	aarch32-tdep.o \
	arc-linux-tdep.o \
	arc-newlib-tdep.o \
	arc-tdep.o \
	arch/aarch32.o \
	arch/arc.o \
	arch/arm.o \
	arch/arm-get-next-pcs.o \
	arch/arm-linux.o \
	arch/i386-linux-tdesc.o \
	arch/i386.o \
	arch/loongarch.o \
	arch/ppc-linux-common.o \
	arch/x86-linux-tdesc-features.o \
	arm-bsd-tdep.o \
	arm-fbsd-tdep.o \
	arm-linux-tdep.o \
	arm-netbsd-tdep.o \
	arm-none-tdep.o \
	arm-obsd-tdep.o \
	arm-pikeos-tdep.o \
	arm-tdep.o \
	arm-wince-tdep.o \
	avr-tdep.o \
	bfin-linux-tdep.o \
	bfin-tdep.o \
	bsd-uthread.o \
	cris-linux-tdep.o \
	cris-tdep.o \
	csky-linux-tdep.o \
	csky-tdep.o \
	dicos-tdep.o \
	fbsd-tdep.o \
	frv-linux-tdep.o \
	frv-tdep.o \
	ft32-tdep.o \
	glibc-tdep.o \
	h8300-tdep.o \
	hppa-bsd-tdep.o \
	hppa-linux-tdep.o \
	hppa-netbsd-tdep.o \
	hppa-obsd-tdep.o \
	hppa-tdep.o \
	i386-bsd-tdep.o \
	i386-darwin-tdep.o \
	i386-dicos-tdep.o \
	i386-fbsd-tdep.o \
	i386-gnu-tdep.o \
	i386-go32-tdep.o \
	i386-linux-tdep.o \
	i386-netbsd-tdep.o \
	i386-obsd-tdep.o \
	i386-sol2-tdep.o \
	i386-tdep.o \
	i386-windows-tdep.o \
	i387-tdep.o \
	iq2000-tdep.o \
	linux-record.o \
	linux-tdep.o \
	lm32-tdep.o \
	m32c-tdep.o \
	m32r-linux-tdep.o \
	m32r-tdep.o \
	m68hc11-tdep.o \
	m68k-bsd-tdep.o \
	m68k-linux-tdep.o \
	m68k-tdep.o \
	mep-tdep.o \
	microblaze-linux-tdep.o \
	microblaze-tdep.o \
	mn10300-linux-tdep.o \
	mn10300-tdep.o \
	moxie-tdep.o \
	msp430-tdep.o \
	netbsd-tdep.o \
	nds32-tdep.o \
	obsd-tdep.o \
	or1k-linux-tdep.o \
	or1k-tdep.o \
	ppc-fbsd-tdep.o \
	ppc-linux-tdep.o \
	ppc-netbsd-tdep.o \
	ppc-obsd-tdep.o \
	ppc-ravenscar-thread.o \
	ppc-sysv-tdep.o \
	ppc64-tdep.o \
	ravenscar-thread.o \
	rl78-tdep.o \
	rs6000-aix-tdep.o \
	rs6000-lynx178-tdep.o \
	rs6000-tdep.o \
	rx-tdep.o \
	s12z-tdep.o \
	s390-linux-tdep.o \
	s390-tdep.o \
	sh-linux-tdep.o \
	sh-netbsd-tdep.o \
	sh-tdep.o \
	sol2-tdep.o \
	solib-aix.o \
	solib-darwin.o \
	solib-dsbt.o \
	solib-frv.o \
	solib-svr4.o \
	solib-svr4-linux.o \
	sparc-linux-tdep.o \
	sparc-netbsd-tdep.o \
	sparc-obsd-tdep.o \
	sparc-ravenscar-thread.o \
	sparc-sol2-tdep.o \
	sparc-tdep.o \
	svr4-tls-tdep.o \
	symfile-mem.o \
	tic6x-linux-tdep.o \
	tic6x-tdep.o \
	v850-tdep.o \
	vax-netbsd-tdep.o \
	vax-tdep.o \
	windows-tdep.o \
	x86-tdep.o \
	xstormy16-tdep.o \
	xtensa-config.o \
	xtensa-linux-tdep.o \
	xtensa-tdep.o \
	z80-tdep.o

# Object files for reading specific types of debug information.
coff_SRCS = coffread.c coff-pe-read.c
dbx_SRCS = dbxread.c
elf_SRCS = elfread.c stap-probe.c dtrace-probe.c
macho_SRCS = machoread.c
mips_SRCS = mipsread.c
xcoff_SRCS = xcoffread.c
FORMAT_SRCS = $(dbx_SRCS) $(mips_SRCS) $(coff_SRCS) $(xcoff_SRCS) $(elf_SRCS) $(macho_SRCS)
FORMAT_OBS = $(patsubst %.c,%.o,$(FORMAT_SRCS))

# The following native-target dependent variables are defined on
# configure.nat.
NAT_FILE = config/nm-linux.h
NATDEPFILES = inf-ptrace.o fork-child.o nat/fork-inferior.o \
		proc-service.o \
		linux-thread-db.o linux-nat.o nat/linux-osdata.o linux-fork.o \
		nat/linux-procfs.o nat/linux-ptrace.o nat/linux-waitpid.o \
		nat/linux-personality.o nat/linux-namespaces.o x86-nat.o nat/x86-dregs.o 		nat/x86-xstate.o amd64-nat.o amd64-linux-nat.o x86-linux-nat.o 		nat/linux-btrace.o 		nat/x86-linux.o nat/x86-linux-dregs.o nat/x86-linux-tdesc.o 		nat/amd64-linux-siginfo.o arch/x86-linux-tdesc-features.o 		arch/i386-linux-tdesc.o arch/amd64-linux-tdesc.o
NAT_CDEPS = $(srcdir)/proc-service.list
LOADLIBES = -ldl $(RDYNAMIC)
MH_CFLAGS = 
XM_CLIBS = 
NAT_GENERATED_FILES = 
NM_H = nm.h
HAVE_NATIVE_GCORE_HOST = 

# Native-target dependent makefile fragment comes in here.

# End of native-target dependent variables.

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
	"CXX_DIALECT=$(CXX_DIALECT)" \
	"CXXFLAGS=$(CXXFLAGS)" \
	"DLLTOOL=$(DLLTOOL)" \
	"LDFLAGS=$(LDFLAGS)" \
	"RANLIB=$(RANLIB)" \
	"MAKEINFO=$(MAKEINFO)" \
	"MAKEINFOFLAGS=$(MAKEINFOFLAGS)" \
	"MAKEINFO_EXTRA_FLAGS=$(MAKEINFO_EXTRA_FLAGS)" \
	"MAKEHTML=$(MAKEHTML)" \
	"MAKEHTMLFLAGS=$(MAKEHTMLFLAGS)" \
	"INSTALL=$(INSTALL)" \
	"INSTALL_PROGRAM=$(INSTALL_PROGRAM)" \
	"INSTALL_SCRIPT=$(INSTALL_SCRIPT)" \
	"INSTALL_DATA=$(INSTALL_DATA)" \
	"RUNTEST=$(RUNTEST)" \
	"RUNTESTFLAGS=$(RUNTESTFLAGS)"

# Flags that we pass when building the testsuite.

# empty for native, $(target_alias)/ for cross
target_subdir = 

CC_FOR_TARGET = ` \
  if [ -f $${rootme}/../gcc/xgcc ] ; then \
    if [ -f $${rootme}/../$(target_subdir)newlib/Makefile ] ; then \
      echo $${rootme}/../gcc/xgcc -B$${rootme}/../gcc/ -idirafter $${rootme}/$(target_subdir)newlib/targ-include -idirafter $${rootsrc}/../$(target_subdir)newlib/libc/include -nostdinc -B$${rootme}/../$(target_subdir)newlib/; \
    else \
      echo $${rootme}/../gcc/xgcc -B$${rootme}/../gcc/; \
    fi; \
  else \
    if [ "$(host_canonical)" = "$(target_canonical)" ] ; then \
      echo $(CC); \
    else \
      t='$(program_transform_name)'; echo gcc | sed -e '' $$t; \
    fi; \
  fi`

CXX_FOR_TARGET = ` \
  if [ -f $${rootme}/../gcc/xg++ ] ; then \
    if [ -f $${rootme}/../$(target_subdir)newlib/Makefile ] ; then \
      echo $${rootme}/../gcc/xg++ -B$${rootme}/../gcc/ -idirafter $${rootme}/$(target_subdir)newlib/targ-include -idirafter $${rootsrc}/../$(target_subdir)newlib/libc/include -nostdinc -B$${rootme}/../$(target_subdir)newlib/; \
    else \
      echo $${rootme}/../gcc/xg++ -B$${rootme}/../gcc/; \
    fi; \
  else \
    if [ "$(host_canonical)" = "$(target_canonical)" ] ; then \
      echo $(CXX); \
    else \
      t='$(program_transform_name)'; echo g++ | sed -e '' $$t; \
    fi; \
  fi`

# The use of $$(x_FOR_TARGET) reduces the command line length by not
# duplicating the lengthy definition.
TARGET_FLAGS_TO_PASS = \
	"prefix=$(prefix)" \
	"exec_prefix=$(exec_prefix)" \
	"against=$(against)" \
	'CC=$$(CC_FOR_TARGET)' \
	"CC_FOR_TARGET=$(CC_FOR_TARGET)" \
	"CFLAGS=$(CFLAGS)" \
	'CXX=$$(CXX_FOR_TARGET)' \
	"CXX_FOR_TARGET=$(CXX_FOR_TARGET)" \
	"CXXFLAGS=$(CXXFLAGS)" \
	"INSTALL=$(INSTALL)" \
	"INSTALL_PROGRAM=$(INSTALL_PROGRAM)" \
	"INSTALL_DATA=$(INSTALL_DATA)" \
	"MAKEINFO=$(MAKEINFO)" \
	"MAKEHTML=$(MAKEHTML)" \
	"RUNTEST=$(RUNTEST)" \
	"RUNTESTFLAGS=$(RUNTESTFLAGS)" \
	"FORCE_PARALLEL=$(FORCE_PARALLEL)" \
	"TESTS=$(TESTS)" \
	"GDB_DEBUG=$(GDB_DEBUG)" \
	"GDBSERVER_DEBUG=$(GDBSERVER_DEBUG)" \


# All source files that go into linking GDB.

# Files that should wind up in SFILES and whose corresponding .o
# should be in COMMON_OBS.
COMMON_SFILES = \
	ada-lang.c \
	ada-tasks.c \
	ada-typeprint.c \
	ada-valprint.c \
	ada-varobj.c \
	addrmap.c \
	agent.c \
	alloc.c \
	annotate.c \
	arch-utils.c \
	async-event.c \
	auto-load.c \
	auxv.c \
	ax-gdb.c \
	ax-general.c \
	bcache.c \
	bfd-target.c \
	block.c \
	blockframe.c \
	break-catch-exec.c \
	break-catch-fork.c \
	break-catch-load.c \
	break-catch-sig.c \
	break-catch-syscall.c \
	break-catch-throw.c \
	break-cond-parse.c \
	breakpoint.c \
	bt-utils.c \
	btrace.c \
	build-id.c \
	buildsym-legacy.c \
	buildsym.c \
	c-lang.c \
	c-typeprint.c \
	c-valprint.c \
	c-varobj.c \
	charset.c \
	cli-out.c \
	complaints.c \
	completer.c \
	copying.c \
	corefile.c \
	corelow.c \
	cp-abi.c \
	cp-namespace.c \
	cp-support.c \
	cp-valprint.c \
	ctfread.c \
	d-lang.c \
	d-namespace.c \
	d-valprint.c \
	dcache.c \
	debug.c \
	debuginfod-support.c \
	dictionary.c \
	disasm.c \
	displaced-stepping.c \
	dummy-frame.c \
	extract-store-integer.c \
	eval.c \
	event-top.c \
	exceptions.c \
	exec.c \
	expprint.c \
	extension.c \
	f-lang.c \
	f-typeprint.c \
	f-valprint.c \
	filesystem.c \
	findcmd.c \
	findvar.c \
	frame.c \
	frame-base.c \
	frame-unwind.c \
	gcore.c \
	gdb-demangle.c \
	gdb_bfd.c \
	gdbtypes.c \
	gmp-utils.c \
	gnu-v2-abi.c \
	gnu-v3-abi.c \
	go-lang.c \
	go-typeprint.c \
	go-valprint.c \
	inf-child.c \
	inf-loop.c \
	infcall.c \
	infcmd.c \
	inferior.c \
	inflow.c \
	infrun.c \
	inline-frame.c \
	interps.c \
	jit.c \
	language.c \
	linespec.c \
	location.c \
	m2-lang.c \
	m2-typeprint.c \
	m2-valprint.c \
	macrocmd.c \
	macroexp.c \
	macroscope.c \
	macrotab.c \
	main.c \
	maint.c \
	maint-test-options.c \
	maint-test-settings.c \
	mem-break.c \
	memattr.c \
	memory-map.c \
	memrange.c \
	memtag.c \
	minidebug.c \
	minsyms.c \
	namespace.c \
	objc-lang.c \
	objfiles.c \
	observable.c \
	opencl-lang.c \
	osabi.c \
	osdata.c \
	p-lang.c \
	p-typeprint.c \
	p-valprint.c \
	parse.c \
	printcmd.c \
	probe.c \
	process-stratum-target.c \
	producer.c \
	progspace.c \
	progspace-and-thread.c \
	prologue-value.c \
	psymtab.c \
	record.c \
	record-btrace.c \
	record-full.c \
	regcache.c \
	regcache-dump.c \
	reggroups.c \
	remote.c \
	remote-fileio.c \
	remote-notif.c \
	reverse.c \
	run-on-main-thread.c \
	rust-lang.c \
	rust-parse.c \
	sentinel-frame.c \
	ser-event.c \
	serial.c \
	skip.c \
	solib.c \
	solib-target.c \
	source.c \
	source-cache.c \
	split-name.c \
	stabsread.c \
	stack.c \
	std-regs.c \
	symfile.c \
	symfile-debug.c \
	symmisc.c \
	symtab.c \
	target.c \
	target-connection.c \
	target-dcache.c \
	target-descriptions.c \
	target-memory.c \
	test-target.c \
	thread.c \
	thread-iter.c \
	tid-parse.c \
	top.c \
	tracectf.c \
	tracefile.c \
	tracefile-tfile.c \
	tracepoint.c \
	trad-frame.c \
	tramp-frame.c \
	target-float.c \
	type-stack.c \
	typeprint.c \
	ui.c \
	ui-file.c \
	ui-out.c \
	ui-style.c \
	user-regs.c \
	utils.c \
	valarith.c \
	valops.c \
	valprint.c \
	value.c \
	varobj.c \
	xml-support.c \
	xml-syscall.c \
	xml-tdesc.c

# Links made at configuration time should not be specified here, since
# SFILES is used in building the distribution archive.
SFILES = \
	ada-exp.y \
	arch/i386.c \
	c-exp.y \
	cp-name-parser.y \
	d-exp.y \
	dtrace-probe.c \
	elf-none-tdep.c \
	f-exp.y \
	gcore-elf.c \
	gdb.c \
	go-exp.y \
	m2-exp.y \
	p-exp.y \
	proc-service.list \
	ser-base.c \
	ser-unix.c \
	sol-thread.c \
	stap-probe.c \
	stub-termcap.c \
	symfile-mem.c \
	ui-file.h \
	$(SUBDIR_CLI_SRCS) \
	$(SUBDIR_MI_SRCS) \
	$(SUBDIR_TARGET_SRCS) \
	$(COMMON_SFILES) \
	$(SUBDIR_GCC_COMPILE_SRCS)

# Header files that need to have srcdir added.  Note that in the cases
# where we use a macro like $(gdbcmd_h), things are carefully arranged
# so that each .h file is listed exactly once (M-x tags-search works
# wrong if TAGS has files twice).  Because this is tricky to get
# right, it is probably easiest just to list .h files here directly.

HFILES_NO_SRCDIR = \
	aarch32-linux-nat.h \
	aarch32-tdep.h \
	aarch64-fbsd-tdep.h \
	aarch64-linux-tdep.h \
	aarch64-nat.h \
	aarch64-ravenscar-thread.h \
	aarch64-tdep.h \
	ada-casefold.h \
	ada-exp.h \
	ada-lang.h \
	addrmap.h \
	alpha-bsd-tdep.h \
	alpha-tdep.h \
	amd64-bsd-nat.h \
	amd64-darwin-tdep.h \
	amd64-fbsd-tdep.h \
	amd64-linux-tdep.h \
	amd64-nat.h \
	amd64-ravenscar-thread.h \
	amd64-tdep.h \
	amd-dbgapi-target.h \
	amdgpu-tdep.h \
	annotate.h \
	arch/aarch32.h \
	arch/aarch64-gcs-linux.h \
	arch/aarch64.h \
	arch/aarch64-insn.h \
	arch/aarch64-mte.h \
	arch/aarch64-mte-linux.h \
	arch/aarch64-scalable-linux.h \
	arch/amd64.h \
	arch/amd64-linux-tdesc.h \
	arch/arc.h \
	arch/arm-get-next-pcs.h \
	arch/arm.h \
	arch/arm-linux.h \
	arch/csky.h \
	arch/i386.h \
	arch/i386-linux-tdesc.h \
	arch/loongarch.h \
	arch/loongarch-insn.h \
	arch/loongarch-syscall.h \
	arch/ppc-linux-common.h \
	arch/ppc-linux-tdesc.h \
	arch/riscv.h \
	arch/tic6x.h \
	arch-utils.h \
	arch/x86-linux-tdesc-features.h \
	arch/x86-linux-tdesc.h \
	arch/xtensa.h \
	arc-linux-tdep.h \
	arc-tdep.h \
	arm-fbsd-tdep.h \
	arm-linux-tdep.h \
	arm-netbsd-tdep.h \
	arm-tdep.h \
	async-event.h \
	auto-load.h \
	auxv.h \
	ax-gdb.h \
	ax.h \
	bcache.h \
	bfd-target.h \
	bfin-tdep.h \
	block.h \
	break-cond-parse.h \
	breakpoint.h \
	bsd-kvm.h \
	bsd-uthread.h \
	btrace.h \
	bt-utils.h \
	build-id.h \
	buildsym.h \
	buildsym-legacy.h \
	c-exp.h \
	cgen-remap.h \
	charset.h \
	charset-list.h \
	c-lang.h \
	cli/cli-cmds.h \
	cli/cli-decode.h \
	cli/cli-interp.h \
	cli/cli-option.h \
	cli/cli-script.h \
	cli/cli-setshow.h \
	cli/cli-style.h \
	cli/cli-utils.h \
	cli-out.h \
	coff-pe-read.h \
	command.h \
	compile/compile-c.h \
	compile/compile-cplus.h \
	compile/compile.h \
	compile/compile-internal.h \
	compile/compile-object-load.h \
	compile/compile-object-run.h \
	compile/gcc-c-plugin.h \
	compile/gcc-cp-plugin.h \
	complaints.h \
	completer.h \
	config/djgpp/langinfo.h \
	config/djgpp/nl_types.h \
	config/i386/nm-x86-gnu.h \
	config/nm-linux.h \
	config/sparc/nm-sol2.h \
	cp-abi.h \
	cp-support.h \
	cris-tdep.h \
	csky-tdep.h \
	c-support.h \
	ctfread.h \
	darwin-nat.h \
	dcache.h \
	debuginfod-support.h \
	defs.h \
	dicos-tdep.h \
	dictionary.h \
	disasm-flags.h \
	disasm.h \
	disasm-selftests.h \
	displaced-stepping.h \
	d-lang.h \
	dummy-frame.h \
	dwarf2/abbrev.h \
	dwarf2/abbrev-table-cache.h \
	dwarf2/aranges.h \
	dwarf2/attribute.h \
	dwarf2/call-site.h \
	dwarf2/cooked-index-entry.h \
	dwarf2/cooked-indexer.h \
	dwarf2/cooked-index.h \
	dwarf2/cooked-index-shard.h \
	dwarf2/cooked-index-worker.h \
	dwarf2/cu.h \
	dwarf2/die.h \
	dwarf2/dwz.h \
	dwarf2/error.h \
	dwarf2/expr.h \
	dwarf2/file-and-dir.h \
	dwarf2/frame.h \
	dwarf2/frame-tailcall.h \
	dwarf2/index-cache.h \
	dwarf2/index-common.h \
	dwarf2/index-write.h \
	dwarf2/leb.h \
	dwarf2/line-header.h \
	dwarf2/line-program.h \
	dwarf2/loc.h \
	dwarf2/macro.h \
	dwarf2/mapped-index.h \
	dwarf2/parent-map.h \
	dwarf2/public.h \
	dwarf2/read-debug-names.h \
	dwarf2/read-gdb-index.h \
	dwarf2/read.h \
	dwarf2/section.h \
	dwarf2/sect-names.h \
	dwarf2/stringify.h \
	dwarf2/tag.h \
	dwarf2/types.h \
	dwarf2/unit-head.h \
	elf-none-tdep.h \
	event-top.h \
	exceptions.h \
	exec.h \
	expop.h \
	expression.h \
	extension.h \
	extension-priv.h \
	extract-store-integer.h \
	f-array-walker.h \
	fbsd-nat.h \
	fbsd-tdep.h \
	f-exp.h \
	filename-seen-cache.h \
	filesystem.h \
	f-lang.h \
	frame-base.h \
	frame.h \
	frame-id.h \
	frame-unwind.h \
	frv-tdep.h \
	ft32-tdep.h \
	gcore-elf.h \
	gcore.h \
	gdbarch-gen.h \
	gdbarch.h \
	gdb_bfd.h \
	gdbcore.h \
	gdb_curses.h \
	gdb-demangle.h \
	gdb_expat.h \
	gdb_proc_service.h \
	gdb-stabs.h \
	gdbthread.h \
	gdbtypes.h \
	gdb_vfork.h \
	gdb_wchar.h \
	glibc-tdep.h \
	gmp-utils.h \
	gnu-nat.h \
	gnu-nat-mig.h \
	go-lang.h \
	gregset.h \
	guile/guile.h \
	guile/guile-internal.h \
	hppa-bsd-tdep.h \
	hppa-linux-offsets.h \
	hppa-tdep.h \
	i386-bsd-nat.h \
	i386-darwin-tdep.h \
	i386-fbsd-tdep.h \
	i386-linux-tdep.h \
	i386-tdep.h \
	i387-tdep.h \
	ia64-libunwind-tdep.h \
	ia64-tdep.h \
	infcall.h \
	inf-child.h \
	inferior.h \
	inferior-iter.h \
	inf-loop.h \
	inf-ptrace.h \
	infrun.h \
	inline-frame.h \
	interps.h \
	jit.h \
	language.h \
	linespec.h \
	linux-fork.h \
	linux-nat.h \
	linux-nat-trad.h \
	linux-record.h \
	linux-tdep.h \
	location.h \
	loongarch-tdep.h \
	m2-exp.h \
	m2-lang.h \
	m32r-tdep.h \
	m68k-tdep.h \
	macroexp.h \
	macroscope.h \
	macrotab.h \
	main.h \
	maint.h \
	mdebugread.h \
	memattr.h \
	memory-map.h \
	memrange.h \
	memtag.h \
	microblaze-tdep.h \
	mi/mi-cmd-break.h \
	mi/mi-cmds.h \
	mi/mi-common.h \
	mi/mi-console.h \
	mi/mi-getopt.h \
	mi/mi-interp.h \
	mi/mi-main.h \
	mi/mi-out.h \
	mi/mi-parse.h \
	minsyms.h \
	mips-fbsd-tdep.h \
	mips-linux-tdep.h \
	mips-netbsd-tdep.h \
	mips-tdep.h \
	mn10300-tdep.h \
	moxie-tdep.h \
	namespace.h \
	nat/aarch64-hw-point.h \
	nat/aarch64-linux.h \
	nat/aarch64-linux-hw-point.h \
	nat/aarch64-mte-linux-ptrace.h \
	nat/aarch64-scalable-linux-ptrace.h \
	nat/aarch64-scalable-linux-sigcontext.h \
	nat/amd64-linux-siginfo.h \
	nat/fork-inferior.h \
	nat/gdb_ptrace.h \
	nat/gdb_thread_db.h \
	nat/glibc_thread_db.h \
	nat/i386-linux.h \
	nat/linux-btrace.h \
	nat/linux-namespaces.h \
	nat/linux-nat.h \
	nat/linux-osdata.h \
	nat/linux-personality.h \
	nat/linux-procfs.h \
	nat/linux-ptrace.h \
	nat/linux-waitpid.h \
	nat/loongarch-hw-point.h \
	nat/loongarch-linux.h \
	nat/loongarch-linux-hw-point.h \
	nat/mips-linux-watch.h \
	nat/netbsd-nat.h \
	nat/ppc-linux.h \
	nat/riscv-linux-tdesc.h \
	nat/windows-nat.h \
	nat/x86-cpuid.h \
	nat/x86-dregs.h \
	nat/x86-gcc-cpuid.h \
	nat/x86-linux-dregs.h \
	nat/x86-linux.h \
	nat/x86-linux-tdesc.h \
	nat/x86-xstate.h \
	nds32-tdep.h \
	netbsd-nat.h \
	netbsd-tdep.h \
	objc-lang.h \
	objfile-flags.h \
	objfiles.h \
	obsd-nat.h \
	obsd-tdep.h \
	observable.h \
	or1k-linux-tdep.h \
	or1k-tdep.h \
	osabi.h \
	osdata.h \
	pager.h \
	parser-defs.h \
	p-lang.h \
	ppc64-tdep.h \
	ppc-fbsd-tdep.h \
	ppc-linux-tdep.h \
	ppc-netbsd-tdep.h \
	ppc-obsd-tdep.h \
	ppc-ravenscar-thread.h \
	ppc-tdep.h \
	probe.h \
	process-stratum-target.h \
	procfs.h \
	proc-utils.h \
	producer.h \
	progspace-and-thread.h \
	progspace.h \
	prologue-value.h \
	psymtab.h \
	python/py-color.h \
	python/py-event.h \
	python/py-events.h \
	python/py-instruction.h \
	python/py-record-btrace.h \
	python/py-record-full.h \
	python/py-record.h \
	python/py-ref.h \
	python/py-stopevent.h \
	python/python.h \
	python/python-internal.h \
	python/py-uiout.h \
	quick-symbol.h \
	ravenscar-thread.h \
	record-btrace.h \
	record-full.h \
	record.h \
	regcache.h \
	regformats/regdef.h \
	reggroups.h \
	registry.h \
	regset.h \
	remote-fileio.h \
	remote.h \
	remote-notif.h \
	riscv-fbsd-tdep.h \
	riscv-linux-tdep.h \
	riscv-ravenscar-thread.h \
	riscv-tdep.h \
	rs6000-aix-tdep.h \
	run-on-main-thread.h \
	rust-exp.h \
	rust-lang.h \
	s390-linux-tdep.h \
	s390-tdep.h \
	scoped-mock-context.h \
	selftest-arch.h \
	sentinel-frame.h \
	ser-base.h \
	ser-event.h \
	serial.h \
	ser-tcp.h \
	ser-unix.h \
	sh-tdep.h \
	sim-regno.h \
	skip.h \
	sol2-tdep.h \
	solib-aix.h \
	solib-darwin.h \
	solib-dsbt.h \
	solib-frv.h \
	solib.h \
	solib-svr4.h \
	solib-svr4-linux.h \
	solib-target.h \
	source-cache.h \
	source.h \
	sparc64-tdep.h \
	sparc-nat.h \
	sparc-ravenscar-thread.h \
	sparc-tdep.h \
	split-name.h \
	stabsread.h \
	stack.h \
	stap-probe.h \
	svr4-tls-tdep.h \
	symfile-add-flags.h \
	symfile.h \
	symtab.h \
	target-connection.h \
	target-dcache.h \
	target-debug.h \
	target-descriptions.h \
	target-float.h \
	target.h \
	target/resume.h \
	target-section.h \
	target/target.h \
	target/wait.h \
	target/waitstatus.h \
	terminal.h \
	test-target.h \
	thread-fsm.h \
	thread-iter.h \
	tic6x-tdep.h \
	tid-parse.h \
	tilegx-tdep.h \
	top.h \
	tracectf.h \
	tracefile.h \
	tracepoint.h \
	trad-frame.h \
	tramp-frame.h \
	tui/tui-command.h \
	tui/tui-data.h \
	tui/tui-disasm.h \
	tui/tui-file.h \
	tui/tui.h \
	tui/tui-hooks.h \
	tui/tui-io.h \
	tui/tui-layout.h \
	tui/tui-location.h \
	tui/tui-regs.h \
	tui/tui-source.h \
	tui/tui-status.h \
	tui/tui-wingeneral.h \
	tui/tui-win.h \
	tui/tui-winsource.h \
	typeprint.h \
	type-stack.h \
	ui-file.h \
	ui.h \
	ui-out.h \
	ui-style.h \
	user-regs.h \
	utils.h \
	valprint.h \
	value.h \
	varobj.h \
	varobj-iter.h \
	vax-tdep.h \
	windows-nat.h \
	windows-tdep.h \
	x86-bsd-nat.h \
	x86-fbsd-nat.h \
	x86-linux-nat.h \
	x86-nat.h \
	x86-tdep.h \
	xcoffread.h \
	xml-builtin.h \
	xml-support.h \
	xml-syscall.h \
	xml-tdesc.h \
	xtensa-tdep.h \
	yy-remap.h \
	z80-tdep.h

# Header files that already have srcdir in them, or which are in objdir.

HFILES_WITH_SRCDIR = \
	../bfd/bfd.h \
	jit-reader.h

# {X,T,NAT}DEPFILES are something of a pain in that it's hard to
# default their values the way we do for SER_HARDWIRE; in the future
# maybe much of the stuff now in {X,T,NAT}DEPFILES will go into other
# variables analogous to SER_HARDWIRE which get defaulted in this
# Makefile.in

DEPFILES = $(TARGET_OBS) $(SER_HARDWIRE) $(NATDEPFILES) $(SIM_OBS)

ALLDEPFILES = \
	arch/aarch32.c \
	arch/aarch64.c \
	arch/aarch64-insn.c \
	arch/aarch64-mte.c \
	arch/aarch64-mte-linux.c \
	arch/aarch64-scalable-linux.c \
	arch/amd64.c \
	arch/arc.c \
	arch/arm.c \
	arch/arm-get-next-pcs.c \
	arch/arm-linux.c \
	arch/i386.c \
	arch/loongarch.c \
	arch/ppc-linux-common.c \
	arch/riscv.c \
	arch/tic6x.c \
	aarch32-tdep.c \
	aarch64-fbsd-nat.c \
	aarch64-fbsd-tdep.c \
	aarch64-linux-nat.c \
	aarch64-linux-tdep.c \
	aarch64-newlib-tdep.c \
	aarch64-ravenscar-thread.c \
	aarch64-tdep.c \
	aix-thread.c \
	alpha-bsd-nat.c \
	alpha-bsd-tdep.c \
	alpha-linux-nat.c \
	alpha-linux-tdep.c \
	alpha-mdebug-tdep.c \
	alpha-netbsd-tdep.c \
	alpha-obsd-tdep.c \
	alpha-tdep.c \
	amd-dbgapi-target.c \
	amd64-bsd-nat.c \
	amd64-darwin-tdep.c \
	amd64-dicos-tdep.c \
	amd64-fbsd-nat.c \
	amd64-fbsd-tdep.c \
	amd64-gnu-tdep.c \
	amd64-linux-nat.c \
	amd64-linux-tdep.c \
	amd64-nat.c \
	amd64-netbsd-nat.c \
	amd64-netbsd-tdep.c \
	amd64-obsd-nat.c \
	amd64-obsd-tdep.c \
	amd64-ravenscar-thread.c \
	amd64-sol2-tdep.c \
	amd64-tdep.c \
	amdgpu-tdep.c \
	arc-linux-nat.c \
	arc-tdep.c \
	arm-bsd-tdep.c \
	arm-fbsd-nat.c \
	arm-fbsd-tdep.c \
	arm-linux-nat.c \
	arm-linux-tdep.c \
	arm-netbsd-nat.c \
	arm-netbsd-tdep.c \
	arm-none-tdep.c \
	arm-obsd-tdep.c \
	arm-tdep.c \
	avr-tdep.c \
	bfin-linux-tdep.c \
	bfin-tdep.c \
	bpf-tdep.c \
	bsd-kvm.c \
	bsd-uthread.c \
	csky-linux-tdep.c \
	csky-tdep.c \
	darwin-nat.c \
	dicos-tdep.c \
	fbsd-nat.c \
	fbsd-tdep.c \
	fork-child.c \
	ft32-tdep.c \
	glibc-tdep.c \
	go32-nat.c \
	h8300-tdep.c \
	hppa-bsd-tdep.c \
	hppa-linux-nat.c \
	hppa-linux-tdep.c \
	hppa-netbsd-nat.c \
	hppa-netbsd-tdep.c \
	hppa-obsd-nat.c \
	hppa-obsd-tdep.c \
	hppa-tdep.c \
	i386-bsd-nat.c \
	i386-bsd-tdep.c \
	i386-darwin-nat.c \
	i386-darwin-tdep.c \
	i386-dicos-tdep.c \
	i386-fbsd-nat.c \
	i386-fbsd-tdep.c \
	i386-gnu-tdep.c \
	i386-linux-nat.c \
	i386-linux-tdep.c \
	i386-netbsd-nat.c \
	i386-netbsd-tdep.c \
	i386-obsd-nat.c \
	i386-obsd-tdep.c \
	i386-sol2-nat.c \
	i386-sol2-tdep.c \
	i386-tdep.c \
	i386-windows-tdep.c \
	i387-tdep.c \
	ia64-libunwind-tdep.c \
	ia64-linux-nat.c \
	ia64-linux-tdep.c \
	ia64-tdep.c \
	ia64-vms-tdep.c \
	inf-ptrace.c \
	linux-fork.c \
	linux-record.c \
	linux-tdep.c \
	lm32-tdep.c \
	loongarch-linux-nat.c \
	loongarch-linux-tdep.c \
	loongarch-tdep.c \
	m32r-linux-nat.c \
	m32r-linux-tdep.c \
	m32r-tdep.c \
	m68hc11-tdep.c \
	m68k-bsd-nat.c \
	m68k-bsd-tdep.c \
	m68k-linux-nat.c \
	m68k-linux-tdep.c \
	m68k-tdep.c \
	microblaze-linux-tdep.c \
	microblaze-tdep.c \
	mingw-hdep.c \
	mips-fbsd-nat.c \
	mips-fbsd-tdep.c \
	mips-linux-nat.c \
	mips-linux-tdep.c \
	mips-netbsd-nat.c \
	mips-netbsd-tdep.c \
	mips-sde-tdep.c \
	mips-tdep.c \
	mips64-obsd-nat.c \
	mips64-obsd-tdep.c \
	msp430-tdep.c \
	netbsd-nat.c \
	netbsd-tdep.c \
	nds32-tdep.c \
	obsd-nat.c \
	obsd-tdep.c \
	or1k-linux-nat.c \
	posix-hdep.c \
	ppc-fbsd-nat.c \
	ppc-fbsd-tdep.c \
	ppc-linux-nat.c \
	ppc-linux-tdep.c \
	ppc-netbsd-nat.c \
	ppc-netbsd-tdep.c \
	ppc-obsd-nat.c \
	ppc-obsd-tdep.c \
	ppc-ravenscar-thread.c \
	ppc-sysv-tdep.c \
	ppc64-tdep.c \
	procfs.c \
	ravenscar-thread.c \
	remote-sim.c \
	riscv-fbsd-nat.c \
	riscv-fbsd-tdep.c \
	riscv-linux-nat.c \
	riscv-linux-tdep.c \
	riscv-none-tdep.c \
	riscv-ravenscar-thread.c \
	riscv-tdep.c \
	rl78-tdep.c \
	rs6000-aix-nat.c \
	rs6000-lynx178-tdep.c \
	rs6000-tdep.c \
	rx-tdep.c \
	s390-linux-nat.c \
	s390-linux-tdep.c \
	s390-tdep.c \
	ser-go32.c \
	ser-mingw.c \
	ser-pipe.c \
	ser-tcp.c \
	ser-uds.c \
	sh-netbsd-nat.c \
	sh-netbsd-tdep.c \
	sh-tdep.c \
	sol2-tdep.c \
	solib-aix.c \
	solib-rocm.c \
	solib-svr4.c \
	sparc-linux-nat.c \
	sparc-linux-tdep.c \
	sparc-nat.c \
	sparc-netbsd-nat.c \
	sparc-netbsd-tdep.c \
	sparc-obsd-tdep.c \
	sparc-ravenscar-thread.c \
	sparc-sol2-nat.c \
	sparc-sol2-tdep.c \
	sparc-tdep.c \
	sparc64-fbsd-nat.c \
	sparc64-fbsd-tdep.c \
	sparc64-linux-nat.c \
	sparc64-linux-tdep.c \
	sparc64-nat.c \
	sparc64-netbsd-nat.c \
	sparc64-netbsd-tdep.c \
	sparc64-obsd-nat.c \
	sparc64-obsd-tdep.c \
	sparc64-sol2-tdep.c \
	sparc64-tdep.c \
	svr4-tls-tdep.c \
	tilegx-linux-nat.c \
	tilegx-linux-tdep.c \
	tilegx-tdep.c \
	v850-tdep.c \
	vax-bsd-nat.c \
	vax-netbsd-tdep.c \
	vax-tdep.c \
	windows-nat.c \
	windows-tdep.c \
	x86-gnu-nat.c \
	x86-nat.c \
	x86-tdep.c \
	xstormy16-tdep.c \
	xtensa-config.c \
	xtensa-linux-nat.c \
	xtensa-linux-tdep.c \
	xtensa-tdep.c \
	xtensa-xtregs.c

# Don't include YYFILES (*.c) because we already include *.y in SFILES,
# and it's more useful to see it in the .y file.
TAGFILES_NO_SRCDIR = $(SFILES) $(HFILES_NO_SRCDIR) $(ALLDEPFILES) \
	$(CONFIG_SRCS)
TAGFILES_WITH_SRCDIR = $(HFILES_WITH_SRCDIR)

# Files that are used to support certain debuginfo formats
DWARF2_SRCS = \
	dwarf2/abbrev.c \
	dwarf2/abbrev-table-cache.c \
	dwarf2/ada-imported.c \
	dwarf2/aranges.c \
	dwarf2/attribute.c \
	dwarf2/cooked-index.c \
	dwarf2/cooked-index-entry.c \
	dwarf2/cooked-index-shard.c \
	dwarf2/cooked-index-worker.c \
	dwarf2/cooked-indexer.c \
	dwarf2/cu.c \
	dwarf2/die.c \
	dwarf2/dwz.c \
	dwarf2/expr.c \
	dwarf2/frame-tailcall.c \
	dwarf2/frame.c \
	dwarf2/index-cache.c \
	dwarf2/index-common.c \
	dwarf2/index-write.c \
	dwarf2/leb.c \
	dwarf2/line-header.c \
	dwarf2/line-program.c \
	dwarf2/loc.c \
	dwarf2/macro.c \
	dwarf2/parent-map.c \
	dwarf2/read.c \
	dwarf2/read-debug-names.c \
	dwarf2/read-gdb-index.c \
	dwarf2/section.c \
	dwarf2/stringify.c \
	dwarf2/unit-head.c
DWARF2_OBS = $(patsubst %.c,%.o, $(DWARF2_SRCS))

COMMON_OBS = $(DEPFILES) $(CONFIG_OBS) $(YYOBJ) \
	mi/mi-common.o \
	version.o \
	xml-builtin.o \
	$(patsubst %.c,%.o,$(COMMON_SFILES)) \
	$(SUBDIR_CLI_OBS) \
	$(SUBDIR_MI_OBS) \
	$(SUBDIR_TARGET_OBS) \
	$(FORMAT_OBS)

SUBDIRS = doc  testsuite data-directory
CLEANDIRS = $(SUBDIRS)

# List of subdirectories in the build tree that must exist.
# This is used to force build failures in existing trees when
# a new directory is added.
# The format here is for the `case' shell command.
REQUIRED_SUBDIRS = doc | testsuite | data-directory

# Parser intermediate files.
YYFILES = \
	ada-exp.c \
	ada-lex.c \
	c-exp.c \
	cp-name-parser.c \
	d-exp.c \
	f-exp.c \
	go-exp.c \
	m2-exp.c \
	p-exp.c

# ada-lex.c is included by another file, so it shouldn't wind up as a
# .o itself.
YYOBJ = $(filter-out ada-lex.o,$(patsubst %.c,%.o,$(YYFILES)))

# Things which need to be built when making a distribution.

DISTSTUFF = $(YYFILES)


# All generated files which can be included by another file.
generated_files = \
	ada-lex.c \
	config.h \
	jit-reader.h \
	$(NAT_GENERATED_FILES) \
	$(NM_H)

# Flags needed to compile Python code
PYTHON_CFLAGS =  -fno-strict-aliasing -fwrapv

all: gdb$(EXEEXT) $(CONFIG_ALL) gdb-gdb.py gdb-gdb.gdb gcore gstack gdb-add-index
	@$(MAKE) $(FLAGS_TO_PASS) DO=all "DODIRS=$(SUBDIRS)" subdir_do

# Rule for compiling .c files in the top-level gdb directory.
# The order-only dependencies ensure that we create the build subdirectories.
%.o: %.c | $(CONFIG_DEP_SUBDIR)
	$(COMPILE) $<
	$(POSTCOMPILE)

$(CONFIG_DEP_SUBDIR):
	$(ECHO_GEN) $(SHELL) $(srcdir)/../install-sh -d $@

# Python files need special flags.
python/%.o: INTERNAL_CFLAGS += $(PYTHON_CFLAGS)

# Rules for compiling .c files in the various source subdirectories.
%.o: $(srcdir)/gdbtk/generic/%.c
	$(COMPILE) $(all_gdbtk_cflags) $<
	$(POSTCOMPILE)

installcheck:

# The check target can not use subdir_do, because subdir_do does not
# use TARGET_FLAGS_TO_PASS.
check: force
	@if [ -f testsuite/Makefile ]; then \
	  rootme=`pwd`; export rootme; \
	  rootsrc=`cd $(srcdir); pwd`; export rootsrc; \
	  cd testsuite; \
	  $(MAKE) $(TARGET_FLAGS_TO_PASS) check; \
	else true; fi

check-perf: force
	@if [ -f testsuite/Makefile ]; then \
	  rootme=`pwd`; export rootme; \
	  rootsrc=`cd $(srcdir); pwd`; export rootsrc; \
	  cd testsuite; \
	  $(MAKE) $(TARGET_FLAGS_TO_PASS) check-perf; \
	else true; fi

check-read1 check-readmore: force
	@if [ -f testsuite/Makefile ]; then \
	  rootme=`pwd`; export rootme; \
	  rootsrc=`cd $(srcdir); pwd`; export rootsrc; \
	  cd testsuite; \
	  $(MAKE) $(TARGET_FLAGS_TO_PASS) $@; \
	else true; fi

check-parallel: force
	@if [ -f testsuite/Makefile ]; then \
	  rootme=`pwd`; export rootme; \
	  rootsrc=`cd $(srcdir); pwd`; export rootsrc; \
	  cd testsuite; \
	  $(MAKE) $(TARGET_FLAGS_TO_PASS) check-parallel; \
	else true; fi

check-all-boards: force
	@if [ -f testsuite/Makefile ]; then \
	  rootme=`pwd`; export rootme; \
	  rootsrc=`cd $(srcdir); pwd`; export rootsrc; \
	  cd testsuite; \
	  $(MAKE) $(TARGET_FLAGS_TO_PASS) check-all-boards; \
	else true; fi

testsuite.lockdir: force
	rm -rf $@
	mkdir -p $@

# The idea is to parallelize testing of multilibs, for example:
#   make -j3 check//sh-hms-sim/{-m1,-m2,-m3,-m3e,-m4}/{,-nofpu}
# will run 3 concurrent sessions of check, eventually testing all 10
# combinations.  GNU make is required for the % pattern to work, as is
# a shell that expands alternations within braces.  If GNU make is not
# used, this rule will harmlessly fail to match.  Used FORCE_PARALLEL to
# prevent serialized checking due to the passed RUNTESTFLAGS.
# FIXME: use config.status --config not --version, when available.
check//%: force testsuite.lockdir
	@if [ -f testsuite/config.status ]; then \
	  rootme=`pwd`; export rootme; \
	  rootsrc=`cd $(srcdir); pwd`; export rootsrc; \
	  target=`echo "$@" | sed 's,//.*,,'`; \
	  variant=`echo "$@" | sed 's,^[^/]*//,,'`; \
	  vardots=`echo "$$variant" | sed 's,/,.,g'`; \
	  testdir=testsuite.$$vardots; \
	  if [ ! -f $$testdir/Makefile ] && [ -f testsuite/config.status ]; then \
	    configargs=`cd testsuite && ./config.status --version | \
	      sed -n -e 's,"$$,,' -e 's,^ *with options ",,p'`; \
	    $(SHELL) $(srcdir)/../mkinstalldirs $$testdir && \
	    (cd $$testdir && \
	     eval $(SHELL) "\"\$$rootsrc/testsuite/configure\" $$configargs" \
			   "\"--srcdir=\$$rootsrc/testsuite\"" \
	     ); \
	  else :; fi && cd $$testdir && \
	  $(MAKE) $(TARGET_FLAGS_TO_PASS) \
	    RUNTESTFLAGS="GDB_LOCK_DIR=$$rootme/testsuite.lockdir --target_board=$$variant $(RUNTESTFLAGS)" \
	    FORCE_PARALLEL=$(if $(FORCE_PARALLEL),1,$(if $(RUNTESTFLAGS),,1)) \
	    "$$target"; \
	else true; fi

# The set of headers checked by 'check-headers' by default.
CHECK_HEADERS = $(HFILES_NO_SRCDIR)

# Try to compile each header in isolation, thus ensuring headers are
# self-contained.
#
# Defaults to checking all $HFILES_NO_SRCDIR headers.
#
# Do:
#
#    make check-headers CHECK_HEADERS="header.h list.h"
#
# to check specific headers.
#
check-headers:
	@echo Checking headers.
	for i in $(CHECK_HEADERS) ; do \
		$(CXX) $(CXX_DIALECT) -x c++-header -c -fsyntax-only \
		$(INTERNAL_CFLAGS) $(CXXFLAGS) $(srcdir)/$$i ; \
	done
.PHONY: check-headers

info install-info clean-info dvi install-dvi pdf install-pdf html install-html: force
	@$(MAKE) $(FLAGS_TO_PASS) DO=$@ "DODIRS=$(SUBDIRS)" subdir_do

# Traditionally "install" depends on "all".  But it may be useful
# not to; for example, if the user has made some trivial change to a
# source file and doesn't care about rebuilding or just wants to save the
# time it takes for make to check that all is up to date.
# install-only is intended to address that need.
install: all
	@$(MAKE) $(FLAGS_TO_PASS) install-only

install-only: $(CONFIG_INSTALL)
	transformed_name=`t='$(program_transform_name)'; \
			  echo gdb | sed -e "$$t"` ; \
		if test "x$$transformed_name" = x; then \
		  transformed_name=gdb ; \
		else \
		  true ; \
		fi ; \
		$(SHELL) $(srcdir)/../mkinstalldirs $(DESTDIR)$(bindir) ; \
		$(INSTALL_PROGRAM_ENV) $(LIBTOOL) --mode=install $(INSTALL_PROGRAM) \
			gdb$(EXEEXT) \
			$(DESTDIR)$(bindir)/$$transformed_name$(EXEEXT) ; \
		$(SHELL) $(srcdir)/../mkinstalldirs $(DESTDIR)$(includedir)/gdb ; \
		$(INSTALL_DATA) jit-reader.h $(DESTDIR)$(includedir)/gdb/jit-reader.h
	if test "x$(HAVE_NATIVE_GCORE_TARGET)$(HAVE_NATIVE_GCORE_HOST)" != x; \
	then \
	  transformed_name=`t='$(program_transform_name)'; \
			    echo gcore | sed -e "$$t"` ; \
		  if test "x$$transformed_name" = x; then \
		    transformed_name=gcore ; \
		  else \
		    true ; \
		  fi ; \
		  $(SHELL) $(srcdir)/../mkinstalldirs $(DESTDIR)$(bindir) ; \
		  $(INSTALL_SCRIPT) gcore \
			  $(DESTDIR)$(bindir)/$$transformed_name; \
	fi
	if test "x${HAVE_GSTACK}" != x; \
	then \
	  transformed_name=`t='$(program_transform_name)'; \
			    echo gstack | sed -e "$$t"` ; \
		  if test "x$$transformed_name" = x; then \
		    transformed_name=gstack ; \
		  else \
		    true ; \
		  fi ; \
		  $(SHELL) $(srcdir)/../mkinstalldirs $(DESTDIR)$(bindir) ; \
		  $(INSTALL_SCRIPT) gstack \
			  $(DESTDIR)$(bindir)/$$transformed_name; \
	fi
	transformed_name=`t='$(program_transform_name)'; \
			  echo gdb-add-index | sed -e "$$t"` ; \
	if test "x$$transformed_name" = x; then \
	  transformed_name=gdb-add-index ; \
	else \
	  true ; \
	fi ; \
	$(INSTALL_SCRIPT) gdb-add-index \
		$(DESTDIR)$(bindir)/$$transformed_name
	@$(MAKE) DO=install "DODIRS=$(SUBDIRS)" $(FLAGS_TO_PASS) subdir_do

install-strip:
	$(MAKE) $(FLAGS_TO_PASS) INSTALL_PROGRAM="$(INSTALL_STRIP_PROGRAM)" \
	  install_sh_PROGRAM="$(INSTALL_STRIP_PROGRAM)" INSTALL_STRIP_FLAG=-s \
	  `test -z '$(STRIP)' || \
	    echo "INSTALL_PROGRAM_ENV=STRIPPROG='$(STRIP)'"` install-only

install-guile:
	$(SHELL) $(srcdir)/../mkinstalldirs $(DESTDIR)$(GDB_DATADIR)/guile/gdb

install-python:
	$(SHELL) $(srcdir)/../mkinstalldirs $(DESTDIR)$(GDB_DATADIR)/python/gdb

uninstall: force $(CONFIG_UNINSTALL)
	transformed_name=`t='$(program_transform_name)'; \
			  echo gdb | sed -e $$t` ; \
		if test "x$$transformed_name" = x; then \
		  transformed_name=gdb ; \
		else \
		  true ; \
		fi ; \
		rm -f $(DESTDIR)$(bindir)/$$transformed_name$(EXEEXT)
		rm -f $(DESTDIR)$(includedir)/gdb/jit-reader.h
	if test "x$(HAVE_NATIVE_GCORE_TARGET)$(HAVE_NATIVE_GCORE_HOST)" != x; \
	then \
	  transformed_name=`t='$(program_transform_name)'; \
			    echo gcore | sed -e "$$t"` ; \
		  if test "x$$transformed_name" = x; then \
		    transformed_name=gcore ; \
		  else \
		    true ; \
		  fi ; \
		  rm -f $(DESTDIR)$(bindir)/$$transformed_name; \
	fi
	if test "x$(HAVE_GSTACK)" != x; \
	then \
	  transformed_name=`t='$(program_transform_name)'; \
			    echo gstack | sed -e "$$t"` ; \
		  if test "x$$transformed_name" = x; then \
		    transformed_name=gstack ; \
		  else \
		    true ; \
		  fi ; \
		  rm -f $(DESTDIR)$(bindir)/$$transformed_name; \
	fi
	transformed_name=`t='$(program_transform_name)'; \
			  echo gdb-add-index | sed -e "$$t"` ; \
	if test "x$$transformed_name" = x; then \
	  transformed_name=gdb-add-index ; \
	else \
	  true ; \
	fi ; \
	rm -f $(DESTDIR)$(bindir)/$$transformed_name
	@$(MAKE) DO=uninstall "DODIRS=$(SUBDIRS)" $(FLAGS_TO_PASS) subdir_do

# We do this by grepping through sources.  If that turns out to be too slow,
# maybe we could just require every .o file to have an initialization routine
# of a given name (top.o -> _initialize_top, etc.).
#
# Note that the set of files with init functions might change, or the names
# of the functions might change, so this files needs to depend on all the
# source files that will be linked into gdb.  However, due to the way
# this Makefile has generally been written, we do this indirectly, by
# computing the list of source files from the list of object files.

INIT_FILES_FILTER_OUT = \
	init.o \
	version.o \
	xml-builtin.o \
	%_S.o \
	%_U.o

INIT_FILES = \
	$(patsubst %.o,%.c, \
	  $(patsubst %-exp.o,%-exp.y, \
	    $(filter-out $(INIT_FILES_FILTER_OUT), $(COMMON_OBS))))

init.c: stamp-init; @true
stamp-init: $(INIT_FILES) config.status $(srcdir)/make-init-c
	$(ECHO_INIT_C)
	$(SILENCE) $(srcdir)/make-init-c \
		$(filter-out config.status $(srcdir)/make-init-c,$^) \
		> init.c-tmp
	$(SILENCE) $(SHELL) $(srcdir)/../move-if-change init.c-tmp init.c
	$(SILENCE) echo stamp > stamp-init

.PRECIOUS: init.c

# Create a library of the gdb object files and build GDB by linking
# against that.
#
# init.o is very important.  It pulls in the rest of GDB.
LIBGDB_OBS = $(sort $(COMMON_OBS)) init.o
libgdb.a: $(LIBGDB_OBS)
	-rm -f libgdb.a
	$(AR) q libgdb.a $(LIBGDB_OBS)
	$(RANLIB) libgdb.a

# Removing the old gdb first works better if it is running, at least on SunOS.
gdb$(EXEEXT): gdb.o $(LIBGDB_OBS) $(CDEPS) $(TDEPLIBS)
	$(SILENCE) rm -f gdb$(EXEEXT)
	$(ECHO_CXXLD) $(CC_LD) $(INTERNAL_LDFLAGS) $(WIN32LDAPP) \
		-o gdb$(EXEEXT) gdb.o $(LIBGDB_OBS) \
		$(TDEPLIBS) $(TUI_LIBRARY) $(CLIBS) $(LOADLIBES)
ifneq ($(CODESIGN_CERT),)
	$(ECHO_SIGN) $(CODESIGN) -s $(CODESIGN_CERT) gdb$(EXEEXT)
endif

# This is useful when debugging GDB, because some Unix's don't let you run GDB
# on itself without copying the executable.  So "make gdb1" will make
# gdb and put a copy in gdb1, and you can run it with "gdb gdb1".
# Removing gdb1 before the copy is the right thing if gdb1 is open
# in another process.
gdb1$(EXEEXT): gdb$(EXEEXT)
	rm -f gdb1$(EXEEXT)
	cp gdb$(EXEEXT) gdb1$(EXEEXT)

# Put the proper machine-specific files first, so M-. on a machine
# specific routine gets the one for the correct machine.  (FIXME: those
# files go in twice; we should be removing them from the main list).

# TAGS depends on all the files that go into it so you can rebuild TAGS
# with `make TAGS' and not have to say `rm TAGS' first.

GDB_NM_FILE = config/nm-linux.h
TAGS: $(TAGFILES_NO_SRCDIR) $(TAGFILES_WITH_SRCDIR)
	@echo Making TAGS
	etags `(test -n "$(GDB_NM_FILE)" && echo "$(srcdir)/$(GDB_NM_FILE)")` \
	`(for i in $(DEPFILES) $(TAGFILES_NO_SRCDIR); do \
		echo $(srcdir)/$$i ; \
	done ; for i in $(TAGFILES_WITH_SRCDIR); do \
		echo $$i ; \
	done) | sed -e 's/\.o$$/\.c/'`

tags: TAGS

clean mostlyclean: $(CONFIG_CLEAN)
	@$(MAKE) $(FLAGS_TO_PASS) DO=clean "DODIRS=$(CLEANDIRS)" subdir_do
	rm -f *.o *.a *~ init.c-tmp init.l-tmp version.c-tmp
	rm -f init.c stamp-init version.c stamp-version
	rm -f gdb$(EXEEXT) core make.log
	rm -f gdb[0-9]$(EXEEXT)
	rm -f xml-builtin.c stamp-xml
	rm -f $(DEPDIR)/*
	for i in $(CONFIG_SRC_SUBDIR); do \
		rm -f $$i/*.o;	\
		rm -f $$i/$(DEPDIR)/*; \
	done

# This used to depend on c-exp.c m2-exp.c TAGS
# I believe this is wrong; the makefile standards for distclean just
# describe removing files; the only sort of "re-create a distribution"
# functionality described is if the distributed files are unmodified.
distclean: clean
	@$(MAKE) $(FLAGS_TO_PASS) DO=distclean "DODIRS=$(CLEANDIRS)" subdir_do
	rm -f nm.h config.status config.h stamp-h b jit-reader.h gcore gstack gstack.in stamp-nmh
	rm -f gdb-gdb.py gdb-gdb.gdb
	rm -f y.output yacc.acts yacc.tmp y.tab.h
	rm -f config.log config.cache
	rm -f config.lt libtool
	rm -f Makefile
	rm -rf $(DEPDIR)
	for i in $(CONFIG_SRC_SUBDIR); do \
		if test -d $$i/$(DEPDIR); then rmdir $$i/$(DEPDIR); fi \
	done

maintainer-clean: local-maintainer-clean do-maintainer-clean distclean
realclean: maintainer-clean

local-maintainer-clean:
	@echo "This command is intended for maintainers to use;"
	@echo "it deletes files that may require special tools to rebuild."
	rm -f c-exp.c \
		cp-name-parser.c \
		ada-lex.c ada-exp.c \
		d-exp.c f-exp.c go-exp.c m2-exp.c p-exp.c
	rm -f TAGS
	rm -f $(YYFILES)
	rm -f nm.h config.status

do-maintainer-clean:
	@$(MAKE) $(FLAGS_TO_PASS) DO=maintainer-clean "DODIRS=$(CLEANDIRS)" \
		subdir_do

diststuff: $(DISTSTUFF) $(PACKAGE).pot $(CATALOGS)
	cd doc; $(MAKE) $(MFLAGS) diststuff

subdir_do: force
	@for i in $(DODIRS); do \
		case $$i in \
		$(REQUIRED_SUBDIRS)) \
			if [ ! -f ./$$i/Makefile ] ; then \
				echo "Missing $$i/Makefile" >&2 ; \
				exit 1 ; \
			fi ;; \
		esac ; \
		if [ -f ./$$i/Makefile ] ; then \
			if (cd ./$$i; \
				$(MAKE) $(FLAGS_TO_PASS) $(DO)) ; then true ; \
			else exit 1 ; fi ; \
		else true ; fi ; \
	done

Makefile: Makefile.in config.status
	$(ECHO_GEN) $(SHELL) config.status $(SILENT_FLAG) $@

.PHONY: run
run: Makefile
	./gdb$(EXEEXT) --data-directory=`pwd`/data-directory $(GDBFLAGS)

jit-reader.h: $(srcdir)/jit-reader.in config.status
	$(ECHO_GEN) $(SHELL) config.status $(SILENT_FLAG) $@

gstack.in gcore.in: %.in : $(srcdir)/%-1.in config.status
	$(ECHO_GEN) $(SHELL) config.status $(SILENT_FLAG) $@

gdb-add-index.in : $(srcdir)/contrib/gdb-add-index.sh config.status
	$(ECHO_GEN) $(SHELL) config.status $(SILENT_FLAG) $@

gstack gcore gdb-add-index: % : %.in version.c
	$(ECHO_GEN) \
	vv=`grep 'version\[\] = ' version.c | grep -o '".*"' | tr -d \"`; \
	sed -e "s,@VERSION@,$$vv," $< > $@
	@chmod +x $@

gdb-gdb.py: $(srcdir)/gdb-gdb.py.in config.status
	$(ECHO_GEN) $(SHELL) config.status $(SILENT_FLAG) $@

gdb-gdb.gdb: $(srcdir)/gdb-gdb.gdb.in config.status
	$(ECHO_GEN) $(SHELL) config.status $(SILENT_FLAG) $@

config.h: stamp-h ; @true
stamp-h: $(srcdir)/config.in config.status
	$(ECHO_GEN) $(SHELL) config.status $(SILENT_FLAG) config.h

nm.h: stamp-nmh ; @true
stamp-nmh: config.status
	$(ECHO_GEN) $(SHELL) config.status $(SILENT_FLAG) nm.h

# Files included from config.status or the configure script.  When
# these change the configure script doesn't need regenerating, but its
# output (and so that of config.status) might change.
config_status_deps = \
	$(srcdir)/configure \
	$(srcdir)/configure.nat \
	$(srcdir)/configure.tgt \
	$(srcdir)/configure.host \
	$(srcdir)/../bfd/development.sh \
	$(srcdir)/../bfd/config.bfd

config.status: $(config_status_deps)
	$(ECHO_GEN) $(SHELL) config.status $(SILENT_FLAG) --recheck

ACLOCAL = aclocal

# Keep these in sync with the includes in acinclude.m4.
aclocal_m4_deps = \
	configure.ac \
	acx_configure_dir.m4 \
	transform.m4 \
	../bfd/bfd.m4 \
	../config/acinclude.m4 \
	../config/enable.m4 \
	../config/plugins.m4 \
	../config/lead-dot.m4 \
	../config/override.m4 \
	../config/largefile.m4 \
	../config/gettext-sister.m4 \
	../config/lib-ld.m4 \
	../config/lib-prefix.m4 \
	../config/lib-link.m4 \
	../config/acx.m4 \
	../config/tcl.m4 \
	../config/depstand.m4 \
	../config/lcmessage.m4 \
	../config/codeset.m4 \
	../config/zlib.m4 \
	../config/zstd.m4 \
	../config/ax_pthread.m4

$(srcdir)/aclocal.m4: # $(aclocal_m4_deps)
	cd $(srcdir) && $(ACLOCAL)

AUTOCONF = autoconf
configure_deps = $(srcdir)/configure.ac $(srcdir)/aclocal.m4
$(srcdir)/configure: # $(configure_deps)
	cd $(srcdir) && $(AUTOCONF)

AUTOHEADER = autoheader
$(srcdir)/config.in: # $(configure_deps)
	cd $(srcdir) && $(AUTOHEADER)
	rm -f stamp-h
	touch $@

# automatic rebuilding in automake-generated Makefiles requires
# this rule in the toplevel Makefile, which, with GNU make, causes
# the desired updates through the implicit regeneration of the Makefile
# and all of its prerequisites.
am--refresh:
	@:

force:

# Documentation!
# GDB QUICK REFERENCE (TeX dvi file, CM fonts)
doc/refcard.dvi:
	cd doc; $(MAKE) refcard.dvi $(FLAGS_TO_PASS)

# GDB QUICK REFERENCE (PostScript output, common PS fonts)
doc/refcard.ps:
	cd doc; $(MAKE) refcard.ps $(FLAGS_TO_PASS)

# GDB MANUAL: TeX dvi file
doc/gdb.dvi:
	cd doc; $(MAKE) gdb.dvi $(FLAGS_TO_PASS)

# GDB MANUAL: info file
doc/gdb.info:
	cd doc; $(MAKE) gdb.info $(FLAGS_TO_PASS)

# Make copying.c from COPYING
$(srcdir)/copying.c: # $(srcdir)/../COPYING3 $(srcdir)/copying.awk
	awk -f $(srcdir)/copying.awk \
		< $(srcdir)/../COPYING3 > $(srcdir)/copying.tmp
	mv $(srcdir)/copying.tmp $(srcdir)/copying.c

version.c: stamp-version; @true
# Note that the obvious names for the temp file are taken by
# create-version.sh.
stamp-version: Makefile version.in $(srcdir)/../bfd/version.h $(srcdir)/../gdbsupport/create-version.sh
	$(ECHO_GEN) $(SHELL) $(srcdir)/../gdbsupport/create-version.sh $(srcdir) \
	    $(host_alias) $(target_alias) version-t.t
	@$(SHELL) $(srcdir)/../move-if-change version-t.t version.c
	@echo stamp > stamp-version


gdb.cxref: $(SFILES)
	cxref -I. $(SFILES) >gdb.cxref

force_update:

# GNU Make has an annoying habit of putting *all* the Makefile variables
# into the environment, unless you include this target as a circumvention.
# Rumor is that this will be fixed (and this target can be removed)
# in GNU Make 4.0.
.NOEXPORT:

# GNU Make 3.63 has a different problem: it keeps tacking command line
# overrides onto the definition of $(MAKE).  This variable setting
# will remove them.
MAKEOVERRIDES =

# Some files need explicit build rules (due to -Werror problems) or due
# to sub-directory fun 'n' games.

# ada-exp.c can appear in srcdir, for releases; or in ., for
# development builds.
ADA_EXP_C = `if test -f ada-exp.c; then echo ada-exp.c; else echo $(srcdir)/ada-exp.c; fi`

ada-exp.o: ada-exp.c
	$(COMPILE) $(ADA_EXP_C)
	$(POSTCOMPILE)

# Message files.  Based on code in gcc/Makefile.in.

# Rules for generating translated message descriptions.  Disabled by
# autoconf if the tools are not available.

.PHONY: all-po install-po uninstall-po clean-po update-po $(PACKAGE).pot

all-po: $(CATALOGS)

# This notation should be acceptable to all Make implementations used
# by people who are interested in updating .po files.
update-po: $(CATALOGS:.gmo=.pox)

# N.B. We do not attempt to copy these into $(srcdir).  The snapshot
# script does that.
%.gmo: %.po
	-test -d po || mkdir po
	$(GMSGFMT) --statistics -o $@ $<

# The new .po has to be gone over by hand, so we deposit it into
# build/po with a different extension.  If build/po/$(PACKAGE).pot
# exists, use it (it was just created), else use the one in srcdir.
%.pox: %.po
	-test -d po || mkdir po
	$(MSGMERGE) $< `if test -f po/$(PACKAGE).pot; \
			then echo po/$(PACKAGE).pot; \
			else echo $(srcdir)/po/$(PACKAGE).pot; fi` -o $@

# This rule has to look for .gmo modules in both srcdir and the cwd,
# and has to check that we actually have a catalog for each language,
# in case they weren't built or included with the distribution.
install-po:
	$(SHELL) $(srcdir)/../mkinstalldirs $(DESTDIR)$(datadir)
	cats="$(CATALOGS)"; for cat in $$cats; do \
	  lang=`basename $$cat | sed 's/\.gmo$$//'`; \
	  if [ -f $$cat ]; then :; \
	  elif [ -f $(srcdir)/$$cat ]; then cat=$(srcdir)/$$cat; \
	  else continue; \
	  fi; \
	  dir=$(localedir)/$$lang/LC_MESSAGES; \
	  echo $(SHELL) $(srcdir)/../mkinstalldirs $(DESTDIR)$$dir; \
	  $(SHELL) $(srcdir)/../mkinstalldirs $(DESTDIR)$$dir || exit 1; \
	  echo $(INSTALL_DATA) $$cat $(DESTDIR)$$dir/$(PACKAGE).mo; \
	  $(INSTALL_DATA) $$cat $(DESTDIR)$$dir/$(PACKAGE).mo; \
	done
uninstall-po:
	cats="$(CATALOGS)"; for cat in $$cats; do \
	  lang=`basename $$cat | sed 's/\.gmo$$//'`; \
	  if [ -f $$cat ]; then :; \
	  elif [ -f $(srcdir)/$$cat ]; then cat=$(srcdir)/$$cat; \
	  else continue; \
	  fi; \
	  dir=$(localedir)/$$lang/LC_MESSAGES; \
	  rm -f $(DESTDIR)$$dir/$(PACKAGE).mo; \
	done
# Delete po/*.gmo only if we are not building in the source directory.
clean-po:
	-if [ ! -f Makefile.in ]; then rm -f po/*.gmo; fi

# Rule for regenerating the message template (gdb.pot).  Instead of
# forcing everyone to edit POTFILES.in, which proved impractical, this
# rule has no dependencies and always regenerates gdb.pot.  This is
# relatively harmless since the .po files do not directly depend on
# it.  The .pot file is left in the build directory.  Since GDB's
# Makefile lacks a canonical list of sources (missing xm, tm and nm
# files) force this rule.
$(PACKAGE).pot: po/$(PACKAGE).pot
po/$(PACKAGE).pot: force
	-test -d po || mkdir po
	sh -e $(srcdir)/po/gdbtext $(XGETTEXT) $(PACKAGE) . $(srcdir)


#
# YACC/LEX dependencies
#
# LANG-exp.c is generated in objdir from LANG-exp.y if it doesn't
# exist in srcdir, then compiled in objdir to LANG-exp.o.  If we
# said LANG-exp.c rather than ./c-exp.c some makes would
# sometimes re-write it into $(srcdir)/c-exp.c.  Remove bogus
# decls for malloc/realloc/free which conflict with everything else.
# Strictly speaking c-exp.c should therefore depend on
# Makefile.in, but that was a pretty big annoyance.

%.c: %.y
	$(ECHO_YACC) $(SHELL) $(YLWRAP) $< y.tab.c $@.tmp -- \
		$(YACC) $(YFLAGS) || (rm -f $@.tmp; false)
	@sed -e '/extern.*malloc/d' \
	     -e '/extern.*realloc/d' \
	     -e '/extern.*free/d' \
	     -e '/include.*malloc.h/d' \
	     -e 's/\([^x]\)malloc/\1xmalloc/g' \
	     -e 's/\([^x]\)realloc/\1xrealloc/g' \
	     -e 's/\([ \t;,(]\)free\([ \t]*[&(),]\)/\1xfree\2/g' \
	     -e 's/\([ \t;,(]\)free$$/\1xfree/g' \
	     -e '/^#line.*y.tab.c/d' \
	     -e 's/YY_NULL/YY_NULLPTR/g' \
	     -e "s/YYSTYPE/$(subst -,_,$*)_YYSTYPE/g" \
	     -e "s/yyalloc/$(subst -,_,$*)_yyalloc/g" \
	     -e "s/yysymbol_kind_t/$(subst -,_,$*)_yysymbol_kind_t/g" \
	  < $@.tmp > $@.new && \
	  rm -f $@.tmp && \
	  mv $@.new $@
%.c: %.l
	$(ECHO_LEX) $(FLEX) -t $< > $@.tmp || (rm -f $@.tmp; false)
	@sed -e '/extern.*malloc/d' \
	     -e '/extern.*realloc/d' \
	     -e '/extern.*free/d' \
	     -e '/include.*malloc.h/d' \
	     -e 's/\([^x]\)malloc/\1xmalloc/g' \
	     -e 's/\([^x]\)realloc/\1xrealloc/g' \
	     -e 's/\([ \t;,(]\)free\([ \t]*[&(),]\)/\1xfree\2/g' \
	     -e 's/\([ \t;,(]\)free$$/\1xfree/g' \
	     -e 's/yy_flex_xrealloc/yyxrealloc/g' \
	     < $@.tmp > $@.new && \
	     rm -f $@.tmp && \
	     mv $@.new $@

# XML rules

xml-builtin.c: stamp-xml; @true
stamp-xml: $(srcdir)/features/feature_to_c.sh Makefile $(XMLFILES)
	$(SILENCE) rm -f xml-builtin.tmp
	$(ECHO_GEN_XML_BUILTIN) AWK="$(AWK)" \
	  $(SHELL) $(srcdir)/features/feature_to_c.sh \
	  xml-builtin.tmp $(XMLFILES)
	$(SILENCE) $(SHELL) $(srcdir)/../move-if-change xml-builtin.tmp xml-builtin.c
	$(SILENCE) echo stamp > stamp-xml

.PRECIOUS: xml-builtin.c

#
# GDBTK sub-directory
#

all-gdbtk: insight$(EXEEXT)

install-gdbtk:
	transformed_name=`t='$(program_transform_name)'; \
		  echo insight | sed -e $$t` ; \
	if test "x$$transformed_name" = x; then \
	  transformed_name=insight ; \
	else \
	  true ; \
	fi ; \
	$(SHELL) $(srcdir)/../mkinstalldirs $(DESTDIR)$(bindir); \
	$(INSTALL_PROGRAM_ENV) $(LIBTOOL) --mode=install $(INSTALL_PROGRAM) \
		insight$(EXEEXT) \
		$(DESTDIR)$(bindir)/$$transformed_name$(EXEEXT) ; \
	$(SHELL) $(srcdir)/../mkinstalldirs \
		$(DESTDIR)$(GDBTK_LIBRARY) ; \
	$(SHELL) $(srcdir)/../mkinstalldirs \
		$(DESTDIR)$(libdir)/insight$(GDBTK_VERSION) ; \
	$(INSTALL_DATA) $(srcdir)/gdbtk/plugins/plugins.tcl \
		$(DESTDIR)$(libdir)/insight$(GDBTK_VERSION)/plugins.tcl ; \
	$(SHELL) $(srcdir)/../mkinstalldirs \
		$(DESTDIR)$(GDBTK_LIBRARY)/images \
		$(DESTDIR)$(GDBTK_LIBRARY)/images2 ; \
	$(SHELL) $(srcdir)/../mkinstalldirs \
		$(DESTDIR)$(GDBTK_LIBRARY)/help \
		$(DESTDIR)$(GDBTK_LIBRARY)/help/images \
		$(DESTDIR)$(GDBTK_LIBRARY)/help/trace ; \
	cd $(srcdir)/gdbtk/library ; \
	for i in *.tcl *.itcl *.ith *.itb images/*.gif images2/*.gif images/icons.txt images2/icons.txt tclIndex help/*.html  help/trace/*.html help/trace/index.toc help/images/*.gif help/images/*.png; \
	  do \
		$(INSTALL_DATA) $$i $(DESTDIR)$(GDBTK_LIBRARY)/$$i ; \
	  done ;

uninstall-gdbtk:
	transformed_name=`t='$(program_transform_name)'; \
		  echo insight | sed -e $$t` ; \
	if test "x$$transformed_name" = x; then \
		transformed_name=insight ; \
	else \
		true ; \
	fi ; \
	rm -f $(DESTDIR)$(bindir)/$$transformed_name$(EXEEXT) ; \
	rm -rf $(DESTDIR)$(GDBTK_LIBRARY)

clean-gdbtk:
	rm -f insight$(EXEEXT)

# Removing the old gdb first works better if it is running, at least on SunOS.
insight$(EXEEXT): gdbtk-main.o libgdb.a $(CDEPS) $(TDEPLIBS)
	rm -f insight$(EXEEXT)
	$(ECHO_CXXLD) $(CC_LD) $(INTERNAL_LDFLAGS) $(WIN32LDAPP) \
		-o insight$(EXEEXT) gdbtk-main.o libgdb.a \
		$(TDEPLIBS) $(TUI_LIBRARY) $(CLIBS) $(LOADLIBES)

gdbres.o: $(srcdir)/gdbtk/gdb.rc $(srcdir)/gdbtk/gdbtool.ico
	$(WINDRES) --include $(srcdir)/gdbtk $(srcdir)/gdbtk/gdb.rc gdbres.o

all_gdbtk_cflags = $(IDE_CFLAGS) $(ITCL_CFLAGS) \
		$(ITK_CFLAGS) $(TCL_CFLAGS) $(TK_CFLAGS) $(X11_CFLAGS) \
		$(GDBTK_CFLAGS) \
		-DGDBTK_LIBRARY=\"$(GDBTK_LIBRARY)\" \
		-DSRC_DIR=\"$(GDBTK_SRC_DIR)\"

#
# Dependency tracking.
#

ifeq ($(DEPMODE),depmode=gcc3)
# Note that we put the dependencies into a .Tpo file, then move them
# into place if the compile succeeds.  We need this because gcc does
# not atomically write the dependency output file.
override COMPILE.post = -c -o $@ -MT $@ -MMD -MP \
	-MF $(@D)/$(DEPDIR)/$(basename $(@F)).Tpo
override POSTCOMPILE = @mv $(@D)/$(DEPDIR)/$(basename $(@F)).Tpo \
	$(@D)/$(DEPDIR)/$(basename $(@F)).Po
else
override COMPILE.pre = source='$<' object='$@' libtool=no \
	DEPDIR=$(DEPDIR) $(DEPMODE) $(depcomp) \
	$(CXX) -x c++ $(CXX_DIALECT)
# depcomp handles atomicity for us, so we don't need a postcompile
# step.
override POSTCOMPILE =
endif

# A list of all the objects we might care about in this build, for
# dependency tracking.
all_object_files = gdb.o $(LIBGDB_OBS) gdbtk-main.o

# All the .deps files to include.
all_deps_files = $(foreach dep,$(patsubst %.o,%.Po,$(all_object_files)),\
    $(dir $(dep))/$(DEPDIR)/$(notdir $(dep)))

# Ensure that generated files are created early.  Use order-only
# dependencies if available.  They require GNU make 3.80 or newer,
# and the .VARIABLES variable was introduced at the same time.
ifdef .VARIABLES
$(all_object_files): | $(generated_files)
else
$(all_object_files) : $(generated_files)
endif

# Dependencies.
-include $(all_deps_files)

# Disable implicit make rules.
include $(srcdir)/disable-implicit-rules.mk

### end of the gdb Makefile.in.
