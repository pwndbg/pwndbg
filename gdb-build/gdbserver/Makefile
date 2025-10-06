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
# See gdb/Makefile.in for guidelines on ordering files and directories.

prefix = /usr/local
exec_prefix = ${prefix}

host_alias = x86_64-pc-linux-gnu
target_alias = x86_64-pc-linux-gnu
program_transform_name = s,y,y,
bindir = ${exec_prefix}/bin
libdir = ${exec_prefix}/lib

CONFIG_SRC_SUBDIR = arch gdbsupport nat target

install_sh = ${SHELL} /home/hussain/GitHub/pwndbg/binutils-gdb/install-sh

SHELL = /bin/bash
EXEEXT = 

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = /usr/bin/install -c
INSTALL_STRIP_PROGRAM = $(install_sh) -c -s
INSTALL_DATA = /usr/bin/install -c -m 644
RANLIB = ranlib --plugin /usr/libexec/gcc/x86_64-linux-gnu/13/liblto_plugin.so

CC = gcc
CXX = g++
CXX_DIALECT = 
AR = ar --plugin /usr/libexec/gcc/x86_64-linux-gnu/13/liblto_plugin.so
AR_FLAGS = rc
STRIP = 

# Dependency tracking information.
DEPMODE = depmode=gcc3
DEPDIR = .deps
depcomp = $(SHELL) $(srcdir)/../depcomp

# Directory containing source files.  Don't clean up the spacing,
# this exact string is matched for by the "configure" script.
srcdir = ../../binutils-gdb/gdbserver
abs_top_srcdir = /home/hussain/GitHub/pwndbg/gdb-build/gdbserver/../../binutils-gdb/gdbserver
abs_srcdir = /home/hussain/GitHub/pwndbg/gdb-build/gdbserver/../../binutils-gdb/gdbserver
VPATH = ../../binutils-gdb/gdbserver

top_builddir = .

include $(srcdir)/../gdb/silent-rules.mk

# Note that these are overridden by GNU make-specific code below if
# GNU make is used.  The overrides implement dependency tracking.
COMPILE.pre = $(CXX) $(CXX_DIALECT)
COMPILE.post = -c -o $@
POSTCOMPILE = @true

INCLUDE_SERVER_H = -include $(srcdir)/server.h

# CXXFLAGS is at the very end on purpose, so that user-supplied flags can
# override internal flags.
COMPILE = $(ECHO_CXX) $(COMPILE.pre) $(INTERNAL_CFLAGS) $(INCLUDE_SERVER_H) \
	$(CXXFLAGS) $(COMPILE.post)

# It is also possible that you will need to add -I/usr/include/sys to the
# CFLAGS section if your system doesn't have fcntl.h in /usr/include (which
# is where it should be according to Posix).

# Set this up with gcc if you have gnu ld and the loader will print out
# line numbers for undefinded refs.
#CC_LD = g++ -static
CC_LD = $(CXX) $(CXX_DIALECT)

# Where is the "include" directory?  Traditionally ../include or ./include
INCLUDE_DIR = ${srcdir}/../include
INCLUDE_DEP = $$(INCLUDE_DIR)

LIBIBERTY_BUILDDIR = ../libiberty
LIBIBERTY_NORMAL = $(LIBIBERTY_BUILDDIR)/libiberty.a
LIBIBERTY_NOASAN = $(LIBIBERTY_BUILDDIR)/noasan/libiberty.a
LIBIBERTY_PIC = $(LIBIBERTY_BUILDDIR)/pic/libiberty.a
LIBIBERTY_FOR_SHLIB = \
  $(if $(wildcard $(LIBIBERTY_NOASAN)),\
       $(LIBIBERTY_NOASAN),\
       $(if $(wildcard $(LIBIBERTY_PIC)),\
	    $(LIBIBERTY_PIC),\
	    $(LIBIBERTY_NORMAL)))
LIBIBERTY = $(LIBIBERTY_NORMAL)

GDBSUPPORT_BUILDDIR = ../gdbsupport
GDBSUPPORT = $(GDBSUPPORT_BUILDDIR)/libgdbsupport.a

# gnulib
GNULIB_PARENT_DIR = ..
include $(GNULIB_PARENT_DIR)/gnulib/Makefile.gnulib.inc

# Where is the INTL library?  Typically in ../intl.
INTL = 
INTL_DEPS = 
INTL_CFLAGS = 

INCSUPPORT = \
	-I$(srcdir)/.. \
	-I..

# All the includes used for CFLAGS and for lint.
# -I. for config files.
# -I${srcdir} for our headers.
# -I$(srcdir)/../gdb/regformats for regdef.h.
#
# We do not include ../target or ../nat in here because headers
# in those directories should be included with the subdirectory.
# e.g.: "target/wait.h".
#
INCLUDE_CFLAGS = \
	-I. \
	-I${srcdir} \
	-I$(srcdir)/../gdb/regformats \
	-I$(srcdir)/.. \
	-I$(INCLUDE_DIR) \
	-I$(srcdir)/../gdb \
	$(INCGNU) \
	$(INCSUPPORT) \
	$(INTL_CFLAGS)

# M{H,T}_CFLAGS, if defined, has host- and target-dependent CFLAGS
# from the config/ directory.
GLOBAL_CFLAGS = ${MT_CFLAGS} ${MH_CFLAGS}
#PROFILE_CFLAGS = -pg

WARN_CFLAGS =  -Wall -Wdeprecated-copy -Wdeprecated-copy-dtor -Wduplicated-cond -Wempty-body -Wimplicit-fallthrough=5 -Wmissing-declarations -Wno-char-subscripts -Wno-mismatched-tags -Wno-sign-compare -Wno-error=maybe-uninitialized -Wno-switch -Wno-unused -Wpointer-arith -Wredundant-move -Wshadow=local -Wstrict-null-sentinel -Wsuggest-override -Wunused-but-set-parameter -Wunused-but-set-variable -Wunused-const-variable=1 -Wunused-function -Wunused-label -Wunused-local-typedefs -Wunused-value -Wunused-variable -Wvla -Wformat -Wformat-nonliteral
WERROR_CFLAGS = 

WARN_CFLAGS_NO_FORMAT = `echo " $(WARN_CFLAGS) " \
		   | sed "s/ -Wformat-nonliteral / -Wno-format-nonliteral /g"`

# These are specifically reserved for setting from the command line
# when running make.  I.E.  "make CFLAGS=-Wmissing-prototypes".
CFLAGS = -g -O2    
CXXFLAGS = -g -O2    
CPPFLAGS = 

PTHREAD_CFLAGS = -pthread
PTHREAD_LIBS = 

WIN32APILIBS = 

MAYBE_LIBICONV = 

# INTERNAL_CFLAGS is the aggregate of all other *CFLAGS macros.
INTERNAL_CFLAGS = \
	${GLOBAL_CFLAGS} \
	${PROFILE_CFLAGS} \
	${INCLUDE_CFLAGS} \
	${CPPFLAGS} \
	$(PTHREAD_CFLAGS) \
	$(WARN_CFLAGS) \
	$(WERROR_CFLAGS) \
	-DGDBSERVER

# LDFLAGS is specifically reserved for setting from the command line
# when running make.
LDFLAGS =  
INTERNAL_LDFLAGS = $(LDFLAGS) -Wl,--dynamic-list=$(srcdir)/proc-service.list

# All source files that go into linking GDB remote server.

SFILES = \
	$(srcdir)/debug.cc \
	$(srcdir)/dll.cc \
	$(srcdir)/gdbreplay.cc \
	$(srcdir)/hostio.cc \
	$(srcdir)/i387-fp.cc \
	$(srcdir)/inferiors.cc \
	$(srcdir)/linux-aarch64-low.cc \
	$(srcdir)/linux-arc-low.cc \
	$(srcdir)/linux-arm-low.cc \
	$(srcdir)/linux-csky-low.cc \
	$(srcdir)/linux-ia64-low.cc \
	$(srcdir)/linux-loongarch-low.cc \
	$(srcdir)/linux-low.cc \
	$(srcdir)/linux-m68k-low.cc \
        $(srcdir)/linux-microblaze-low.cc \
	$(srcdir)/linux-mips-low.cc \
	$(srcdir)/linux-or1k-low.cc \
	$(srcdir)/linux-ppc-low.cc \
	$(srcdir)/linux-riscv-low.cc \
	$(srcdir)/linux-s390-low.cc \
	$(srcdir)/linux-sh-low.cc \
	$(srcdir)/linux-sparc-low.cc \
	$(srcdir)/linux-x86-low.cc \
	$(srcdir)/linux-xtensa-low.cc \
	$(srcdir)/mem-break.cc \
	$(srcdir)/netbsd-aarch64-low.cc \
	$(srcdir)/netbsd-amd64-low.cc \
	$(srcdir)/netbsd-i386-low.cc \
	$(srcdir)/netbsd-low.cc \
	$(srcdir)/netbsd-low.h \
	$(srcdir)/proc-service.cc \
	$(srcdir)/proc-service.list \
	$(srcdir)/regcache.cc \
	$(srcdir)/remote-utils.cc \
	$(srcdir)/server.cc \
	$(srcdir)/symbol.cc \
	$(srcdir)/target.cc \
	$(srcdir)/thread-db.cc \
	$(srcdir)/utils.cc \
	$(srcdir)/win32-i386-low.cc \
	$(srcdir)/win32-low.cc \
	$(srcdir)/x86-low.cc \
	$(srcdir)/../gdb/alloc.c \
	$(srcdir)/../gdb/arch/arc.c \
	$(srcdir)/../gdb/arch/arm.c \
	$(srcdir)/../gdb/arch/arm-get-next-pcs.c \
	$(srcdir)/../gdb/arch/arm-linux.c \
	$(srcdir)/../gdb/arch/csky.c \
	$(srcdir)/../gdb/arch/loongarch.c \
	$(srcdir)/../gdb/arch/ppc-linux-common.c \
	$(srcdir)/../gdb/arch/riscv.c \
	$(srcdir)/../gdb/nat/aarch64-mte-linux-ptrace.c \
	$(srcdir)/../gdb/nat/aarch64-scalable-linux-ptrace.c \
	$(srcdir)/../gdb/nat/linux-btrace.c \
	$(srcdir)/../gdb/nat/linux-namespaces.c \
	$(srcdir)/../gdb/nat/linux-osdata.c \
	$(srcdir)/../gdb/nat/linux-personality.c \
	$(srcdir)/../gdb/nat/mips-linux-watch.c \
	$(srcdir)/../gdb/nat/ppc-linux.c \
	$(srcdir)/../gdb/nat/riscv-linux-tdesc.c \
	$(srcdir)/../gdb/nat/fork-inferior.c \
	$(srcdir)/../gdb/target/target.c \
	$(srcdir)/../gdb/target/waitstatus.c

DEPFILES =  linux-low.o nat/linux-osdata.o nat/linux-procfs.o nat/linux-ptrace.o nat/linux-waitpid.o nat/linux-personality.o nat/linux-namespaces.o fork-child.o nat/fork-inferior.o linux-x86-low.o x86-low.o nat/x86-dregs.o nat/x86-xstate.o i387-fp.o arch/i386.o arch/amd64.o linux-x86-tdesc.o nat/linux-btrace.o nat/x86-linux.o nat/x86-linux-dregs.o nat/x86-linux-tdesc.o nat/amd64-linux-siginfo.o arch/x86-linux-tdesc-features.o arch/amd64-linux-tdesc.o arch/i386-linux-tdesc.o thread-db.o proc-service.o

LIBOBJS = 

SOURCES = $(SFILES)
TAGFILES = $(SOURCES)

OBS = \
	alloc.o \
	ax.o \
	debug.o \
	dll.o \
	hostio.o \
	inferiors.o \
	mem-break.o \
	notif.o \
	regcache.o \
	remote-utils.o \
	server.o \
	symbol.o \
	target.o \
	tdesc.o \
	tracepoint.o \
	utils.o \
	version.o \
	target/target.o \
	target/waitstatus.o \
	$(DEPFILES) \
	$(LIBOBJS) \
	$(XML_BUILTIN)

GDBREPLAY_OBS = \
	gdbreplay.o \
	utils.o \
	version.o

GDBSERVER_LIBS = -ldl $(PTHREAD_LIBS)
XM_CLIBS = 
CDEPS = $(srcdir)/proc-service.list

# XML files to compile in to gdbserver, if any.
XML_DIR = $(srcdir)/../gdb/features
XML_FILES = 
XML_BUILTIN = 

IPA_DEPFILES = linux-amd64-ipa.o linux-x86-tdesc-ipa.o arch/amd64-ipa.o arch/x86-linux-tdesc-features-ipa.o arch/amd64-linux-tdesc-ipa.o
extra_libraries =  libinproctrace.so

FLAGS_TO_PASS = \
	"prefix=$(prefix)" \
	"exec_prefix=$(exec_prefix)" \
	"libdir=$(libdir)" \
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

# All generated files which can be included by another file.
generated_files = config.h

all: gdbserver$(EXEEXT) gdbreplay$(EXEEXT) $(extra_libraries)

# Traditionally "install" depends on "all".  But it may be useful
# not to; for example, if the user has made some trivial change to a
# source file and doesn't care about rebuilding or just wants to save the
# time it takes for make to check that all is up to date.
# install-only is intended to address that need.
install: all
	@$(MAKE) $(FLAGS_TO_PASS) install-only

install-only:
	n=`echo gdbserver | sed '$(program_transform_name)'`; \
	if [ x$$n = x ]; then n=gdbserver; else true; fi; \
	if [ x"$(IPA_DEPFILES)" != x ]; then \
		$(SHELL) $(srcdir)/../mkinstalldirs $(DESTDIR)$(libdir); \
		$(INSTALL_PROGRAM_ENV) $(INSTALL_PROGRAM) $(IPA_LIB) $(DESTDIR)$(libdir)/$(IPA_LIB); \
	fi; \
	$(SHELL) $(srcdir)/../mkinstalldirs $(DESTDIR)$(bindir); \
	$(INSTALL_PROGRAM_ENV) $(INSTALL_PROGRAM) gdbserver$(EXEEXT) $(DESTDIR)$(bindir)/$$n$(EXEEXT)

install-strip:
	$(MAKE) $(FLAGS_TO_PASS) INSTALL_PROGRAM="$(INSTALL_STRIP_PROGRAM)" \
	  install_sh_PROGRAM="$(INSTALL_STRIP_PROGRAM)" INSTALL_STRIP_FLAG=-s \
	  `test -z '$(STRIP)' || \
	    echo "INSTALL_PROGRAM_ENV=STRIPPROG='$(STRIP)'"` install-only

uninstall: force
	n=`echo gdbserver | sed '$(program_transform_name)'`; \
	if [ x$$n = x ]; then n=gdbserver; else true; fi; \
	if [ x"$(IPA_DEPFILES)" != x ]; then \
		rm -f $(DESTDIR)$(libdir)/$(IPA_LIB); \
	fi; \
	rm -f $(DESTDIR)/$(bindir)/$$n$(EXEEXT)

installcheck:
check:
info dvi pdf:
install-info:
install-dvi:
install-pdf:
html:
install-html:
clean-info:

gdbserver$(EXEEXT): $(sort $(OBS)) ${CDEPS} $(LIBGNU) $(LIBIBERTY) \
		$(INTL_DEPS) $(GDBSUPPORT)
	$(SILENCE) rm -f gdbserver$(EXEEXT)
	$(ECHO_CXXLD) $(CC_LD) $(INTERNAL_CFLAGS) $(INTERNAL_LDFLAGS) \
		$(CXXFLAGS) \
		-o gdbserver$(EXEEXT) $(OBS) $(GDBSUPPORT) $(LIBGNU) \
		$(LIBGNU_EXTRA_LIBS) $(LIBIBERTY) $(INTL) \
		$(GDBSERVER_LIBS) $(XM_CLIBS) $(WIN32APILIBS) $(MAYBE_LIBICONV)

gdbreplay$(EXEEXT): $(sort $(GDBREPLAY_OBS)) $(LIBGNU) $(LIBIBERTY) \
		$(INTL_DEPS) $(GDBSUPPORT)
	$(SILENCE) rm -f gdbreplay$(EXEEXT)
	$(ECHO_CXXLD) $(CC_LD) $(INTERNAL_CFLAGS) $(INTERNAL_LDFLAGS) \
		$(CXXFLAGS) \
		-o gdbreplay$(EXEEXT) $(GDBREPLAY_OBS) $(XM_CLIBS) \
		$(GDBSUPPORT) $(LIBGNU) $(LIBGNU_EXTRA_LIBS) \
		$(LIBIBERTY) $(INTL) $(WIN32APILIBS)

IPA_OBJS = \
	alloc-ipa.o \
	ax-ipa.o \
	gdbsupport/common-utils-ipa.o \
	gdbsupport/errors-ipa.o \
	gdbsupport/format-ipa.o \
	gdbsupport/print-utils-ipa.o \
	gdbsupport/rsp-low-ipa.o \
	gdbsupport/safe-strerror-ipa.o \
	gdbsupport/tdesc-ipa.o \
	regcache-ipa.o \
	remote-utils-ipa.o \
	tdesc-ipa.o \
	tracepoint-ipa.o \
	utils-ipa.o \
	${IPA_DEPFILES}

IPA_LIB = libinproctrace.so

$(IPA_LIB): $(sort $(IPA_OBJS)) ${CDEPS}
	$(SILENCE) rm -f $(IPA_LIB)
	$(ECHO_CXXLD) $(CC_LD) -shared -fPIC -Wl,--soname=$(IPA_LIB) \
		-Wl,--no-undefined $(INTERNAL_CFLAGS) $(INTERNAL_LDFLAGS) \
		 $(CXXFLAGS) \
		-o $(IPA_LIB) ${IPA_OBJS} $(LIBIBERTY_FOR_SHLIB) -ldl -pthread

# Put the proper machine-specific files first, so M-. on a machine
# specific routine gets the one for the correct machine.
# The xyzzy stuff below deals with empty DEPFILES
TAGS:	${TAGFILES}
	etags \
	  `for i in yzzy ${DEPFILES}; do \
	     if [ x$$i != xyzzy ]; then \
	       echo ${srcdir}/$$i | \
		 sed -e 's,/\(\(arch\|nat\|target\)/.*\)\.o$$,/../gdb/\1.c,' \
		     -e 's/\.o$$/\.cc/'; \
	     fi; \
	   done` \
	  ${TAGFILES}
tags: TAGS

mostlyclean clean:
	rm -f *.o ${ADD_FILES} *~
	rm -f gdbserver$(EXEEXT) gdbreplay$(EXEEXT) core make.log
	rm -f $(IPA_LIB)
	rm -f *-generated.cc
	rm -f stamp-xml
	rm -f $(DEPDIR)/*.Po
	for i in $(CONFIG_SRC_SUBDIR); do \
		rm -f $$i/*.o;	\
		rm -f $$i/$(DEPDIR)/*; \
	done

maintainer-clean realclean distclean: clean
	rm -f Makefile config.status config.h stamp-h config.log config.cache
	for i in $(CONFIG_SRC_SUBDIR); do \
		rmdir $$i/$(DEPDIR); \
	done

config.h: stamp-h ; @true
stamp-h: config.in config.status
	$(SHELL) ./config.status config.h

Makefile: Makefile.in config.status
	$(SHELL) ./config.status $@

config.status: configure configure.srv $(srcdir)/../bfd/development.sh
	$(SHELL) ./config.status --recheck

# automatic rebuilding in automake-generated Makefiles requires
# this rule in the toplevel Makefile, which, with GNU make, causes
# the desired updates through the implicit regeneration of the Makefile
# and all of its prerequisites.
am--refresh:
	@:

force:

version-generated.cc: Makefile $(srcdir)/../gdb/version.in $(srcdir)/../bfd/version.h $(srcdir)/../gdbsupport/create-version.sh
	$(ECHO_GEN) $(SHELL) $(srcdir)/../gdbsupport/create-version.sh $(srcdir)/../gdb \
		$(host_alias) $(target_alias) $@

xml-builtin-generated.cc: stamp-xml; @true
stamp-xml: $(XML_DIR)/feature_to_c.sh Makefile $(XML_FILES)
	$(SILENCE) rm -f xml-builtin.tmp
	$(ECHO_GEN_XML_BUILTIN_GENERATED) $(SHELL) $(XML_DIR)/feature_to_c.sh \
		xml-builtin.tmp $(XML_FILES)
	$(SILENCE) $(SHELL) $(srcdir)/../move-if-change xml-builtin.tmp xml-builtin-generated.cc
	$(SILENCE) echo stamp > stamp-xml

.PRECIOUS: xml-builtin.cc

# GNU Make has an annoying habit of putting *all* the Makefile variables
# into the environment, unless you include this target as a circumvention.
# Rumor is that this will be fixed (and this target can be removed)
# in GNU Make 4.0.
.NOEXPORT:

# GNU Make 3.63 has a different problem: it keeps tacking command line
# overrides onto the definition of $(MAKE).  This variable setting
# will remove them.
MAKEOVERRIDES =

regdat_sh = $(srcdir)/../gdb/regformats/regdat.sh
osabi_def = $(srcdir)/../gdbsupport/osabi.def

# Undo gnulib replacements for the IPA shared library build.
# The gnulib headers are still needed, but gnulib is not linked
# into the IPA lib so replacement apis don't work.
UNDO_GNULIB_CFLAGS = \
	-Drpl_strerror_r=strerror_r \
	-Drpl_free=free \
	-Drpl_malloc=malloc \
	-Drpl_realloc=realloc

# Note, we only build the IPA if -fvisibility=hidden is supported in
# the first place.
IPAGENT_CFLAGS = \
	$(INTERNAL_CFLAGS) \
	$(UNDO_GNULIB_CFLAGS) \
	-fPIC -DIN_PROCESS_AGENT \
	-fvisibility=hidden

# CXXFLAGS is at the very end on purpose, so that user-supplied flags can
# override internal flags.
IPAGENT_COMPILE = $(ECHO_CXX) $(COMPILE.pre) $(IPAGENT_CFLAGS) \
	$(INCLUDE_SERVER_H) $(CXXFLAGS) $(COMPILE.post)

# Rules for special cases.

ax-ipa.o: ax.cc
	$(IPAGENT_COMPILE) $(WARN_CFLAGS_NO_FORMAT) $<
	$(POSTCOMPILE)

ax.o: ax.cc
	$(COMPILE) $(WARN_CFLAGS_NO_FORMAT) $<
	$(POSTCOMPILE)

# Rules for objects that go in the in-process agent.

arch/%-ipa.o: ../gdb/arch/%.c
	$(IPAGENT_COMPILE) -x c++ $<
	$(POSTCOMPILE)

gdbsupport/%-ipa.o: ../gdbsupport/%.cc
	$(IPAGENT_COMPILE) $<
	$(POSTCOMPILE)

%-ipa.o: %-generated.cc
	$(IPAGENT_COMPILE) $<
	$(POSTCOMPILE)

%-ipa.o: %.cc
	$(IPAGENT_COMPILE) $<
	$(POSTCOMPILE)

%-ipa.o: ../gdb/%.c
	$(IPAGENT_COMPILE) -x c++ $<
	$(POSTCOMPILE)

# Note: Between two matching pattern rules, GNU Make 3.81 chooses the first one.
# Therefore, this one needs to be before "%.o: %.cc" for it to be considered for
# files such as linux-amd64-ipa.o generated from linux-amd64-ipa.cc.
#
# Later versions of GNU Make choose the rule with the shortest stem, so it would
# work in any order.

%-ipa.o: %-ipa.cc
	$(IPAGENT_COMPILE) $<
	$(POSTCOMPILE)

# Rules for objects that go in the gdbserver binary.

arch/%.o: ../gdb/arch/%.c
	$(COMPILE) -x c++ $<
	$(POSTCOMPILE)

%.o: %-generated.cc
	$(COMPILE) $<
	$(POSTCOMPILE)

%.o: %.cc
	$(COMPILE) $<
	$(POSTCOMPILE)

nat/%.o: ../gdb/nat/%.c
	$(COMPILE) -x c++ $<
	$(POSTCOMPILE)

target/%.o: ../gdb/target/%.c
	$(COMPILE) -x c++ $<
	$(POSTCOMPILE)

%.o: ../gdb/%.c
	$(COMPILE) -x c++ $<
	$(POSTCOMPILE)

# Rules for register format descriptions.  Suffix destination files with
# -generated to identify and clean them easily.

%-generated.cc: ../gdb/regformats/%.dat $(osabi_def) $(regdat_sh)
	$(ECHO_REGDAT) $(SHELL) $(regdat_sh) $< $(osabi_def) $@

%-generated.cc: ../gdb/regformats/rs6000/%.dat $(osabi_def) $(regdat_sh)
	$(ECHO_REGDAT) $(SHELL) $(regdat_sh) $< $(osabi_def) $@

# Rule for gdbreplay.o.  This is the same as COMPILE, but includes common-defs.h
# instead of server.h.
gdbreplay.o: gdbreplay.cc
	$(ECHO_CXX) $(COMPILE.pre) $(INTERNAL_CFLAGS) $(CXXFLAGS) \
		-include gdbsupport/common-defs.h $(COMPILE.post) $<

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
	$(CXX) $(CXX_DIALECT)
# depcomp handles atomicity for us, so we don't need a postcompile
# step.
override POSTCOMPILE =
endif

# A list of all the objects we might care about in this build, for
# dependency tracking.
all_object_files = $(OBS) $(GDBREPLAY_OBS) $(IPA_OBJS)

# Ensure that generated files are created early.  Use order-only
# dependencies if available.  They require GNU make 3.80 or newer,
# and the .VARIABLES variable was introduced at the same time.
ifdef .VARIABLES
$(all_object_files): | $(generated_files)
else
$(all_object_files) : $(generated_files)
endif

# All the .deps files to include.
all_deps_files = $(foreach dep,$(patsubst %.o,%.Po,$(all_object_files)),\
		   $(dir $(dep))/$(DEPDIR)/$(notdir $(dep)))

# Dependencies.
-include $(all_deps_files)

# Disable implicit make rules.
include $(srcdir)/../gdb/disable-implicit-rules.mk

# Do not delete intermediate files (e.g. *-generated.cc).
.SECONDARY:

# This is the end of "Makefile.in".
