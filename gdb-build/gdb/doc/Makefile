##Copyright (C) 1991-2025 Free Software Foundation, Inc.

# Makefile for GDB documentation.
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

srcdir = ../../../binutils-gdb/gdb/doc
VPATH = ../../../binutils-gdb/gdb/doc

prefix = /usr/local

infodir = ${datarootdir}/info
datarootdir = ${prefix}/share
docdir = ${datarootdir}/doc/${PACKAGE}
dvidir = ${docdir}
pdfdir = ${docdir}
htmldir = ${docdir}
mandir = ${datarootdir}/man
man1dir = $(mandir)/man1
man5dir = $(mandir)/man5

transform = s,y,y,

include $(srcdir)/../silent-rules.mk

SHELL = /bin/bash

LN_S = ln -s

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = /usr/bin/install -c
INSTALL_DATA = /usr/bin/install -c -m 644

SYSTEM_GDBINIT = /etc/gdb/gdbinit
SYSTEM_GDBINIT_DIR = 

mkinstalldirs = $(SHELL) $(srcdir)/../../mkinstalldirs

# main GDB source directory
gdbdir = $(srcdir)/..

# where to find texinfo; GDB dist should include a recent one
TEXIDIR=${gdbdir}/../texinfo

# where to find makeinfo, preferably one designed for texinfo-2
MAKEINFO = makeinfo --split-size=5000000
MAKEINFOFLAGS = 
MAKEINFO_EXTRA_FLAGS =  -DHAVE_MAKEINFO_CLICK
MAKEINFO_CMD = $(MAKEINFO) $(MAKEINFOFLAGS) $(MAKEINFO_EXTRA_FLAGS)

MAKEHTML = $(MAKEINFO_CMD) --html
MAKEHTMLFLAGS =

# where to find texi2roff, ditto
TEXI2ROFF=texi2roff

# Where to find texi2dvi.  The use of --build and --build-dir options
# mean that at least texinfo 4.9 is required.
TEXI2DVI=texi2dvi
TEXI2DVI_TMPDIR=texi2dvi_tmpdir
TEXI2DVI_CMD = rm -fr $(TEXI2DVI_TMPDIR)/$(subst .,_,$@) \
		&& mkdir -p $(TEXI2DVI_TMPDIR)/$(subst .,_,$@) \
		&& $(TEXI2DVI) --build=tidy \
			       --build-dir=$(TEXI2DVI_TMPDIR)/$(subst .,_,$@)

# Package to install the docs under
PACKAGE = gdb

# Package version and bug-reporting URL.
PKGVERSION = (GDB) 
BUGURL_TEXI = @uref{https://www.gnu.org/software/gdb/bugs/}

# Where is the source dir for the READLINE library doc?  
# Traditionally readline is in .. or .
READLINE_DIR = ${gdbdir}/../readline/readline/doc
READLINE_TEXI_INCFLAG = 

# The GDB/MI docs come from a sibling directory ../mi
GDBMI_DIR = ${gdbdir}/mi

SET_TEXINPUTS = \
   TEXINPUTS=${TEXIDIR}:.:$(srcdir):$(READLINE_DIR):$(GDBMI_DIR):$$TEXINPUTS

# Files which should be generated via 'info' and installed by 'install-info'
INFO_DEPS = gdb.info stabs.info annotate.info

# Files which should be generated via 'dvi' and installed by 'install-dvi'
DVIFILES = gdb.dvi stabs.dvi refcard.dvi annotate.dvi
# Files which should be generated via 'pdf' and installed by 'install-pdf'
PDFFILES = gdb.pdf stabs.pdf refcard.pdf annotate.pdf
# Files which should be generated via 'html' and installed by 'install-html'
HTMLFILES =  gdb/index.html stabs/index.html annotate/index.html
HTMLFILES_INSTALL = gdb stabs annotate

# There may be alternate predefined collections of switches to configure
# the GDB manual.  Normally this is not done in synch with the software
# config system, since this choice tends to be independent; most people
# want a doc config of `all' for a generic manual, regardless of sw config.
DOC_CONFIG = all

# This list of sed edits will edit the GDB reference card
# for what fonts and what papersize to use.
# By default (NO edits applied), the refcard uses:
#    - Computer Modern (CM) fonts
#    - US letter paper (8.5x11in)
# List some of the following files for alternative fonts and paper:
#  a4rc.sed     use A4 paper (297 x 210 mm)
#  psrc.sed     use PostScript fonts (Karl Berry short TeX names)
# lpsrc.sed     use PostScript fonts (full PostScript names in TeX)
# e.g. for A4, Postscript:  REFEDITS = a4rc.sed psrc.sed
#      for A4, CM fonts:    REFEDITS = a4rc.sed
#      for US, PS fonts:    REFEDITS = psrc.sed
#      for default:
REFEDITS =

# Don Knuth's TeX formatter
TEX = tex
PDFTEX = pdftex

# Program to generate Postscript files from DVI files.
DVIPS = dvips

# Readline includes.
READLINE_SYSTEM_DOC_INCLUDES =
READLINE_INTREE_DOC_INCLUDES = $(READLINE_DIR)/rluser.texi $(READLINE_DIR)/hsuser.texi
READLINE_DOC_SOURCE_INCLUDES = $(READLINE_SYSTEM_DOC_INCLUDES)

# Main GDB manual
# Note that this unconditionally includes the readline texi files,
# even when --with-system-readline is used.  This is harmless because
# these are only used as dependencies.
GDB_DOC_SOURCE_INCLUDES = \
	$(srcdir)/fdl.texi \
	$(srcdir)/gpl.texi \
	$(srcdir)/agentexpr.texi \
	$(READLINE_DOC_SOURCE_INCLUDES)
GDB_DOC_BUILD_INCLUDES = \
	gdb-cfg.texi \
	GDBvn.texi
GDB_DOC_FILES = \
	$(srcdir)/gdb.texinfo \
	$(srcdir)/guile.texi \
	$(srcdir)/python.texi \
	$(GDB_DOC_SOURCE_INCLUDES) \
	$(GDB_DOC_BUILD_INCLUDES)

# Stabs manual: All files
STABS_DOC_SOURCE_INCLUDES = \
	$(srcdir)/fdl.texi
STABS_DOC_BUILD_INCLUDES = \
	gdb-cfg.texi \
	GDBvn.texi
STABS_DOC_FILES = \
	$(srcdir)/stabs.texinfo \
	$(STABS_DOC_SOURCE_INCLUDES) \
	$(STABS_DOC_BUILD_INCLUDES)

# Annotate migration document
ANNOTATE_DOC_SOURCE_INCLUDES = \
	$(srcdir)/fdl.texi
ANNOTATE_DOC_BUILD_INCLUDES = \
	gdb-cfg.texi \
	GDBvn.texi
ANNOTATE_DOC_FILES = \
	$(srcdir)/annotate.texinfo \
	$(ANNOTATE_DOC_SOURCE_INCLUDES) \
	$(ANNOTATE_DOC_BUILD_INCLUDES)

# Options to extract the man page from gdb.texinfo
MANCONF = -Dman

TEXI2POD = perl $(srcdir)/../../etc/texi2pod.pl \
		$(MAKEINFOFLAGS) $(MAKEINFO_EXTRA_FLAGS) -I $(srcdir)


POD2MAN = pod2man --center="GNU Development Tools"

# List of man pages generated from gdb.texi
MAN1S = gdb.1 gdbserver.1 gcore.1 gstack.1 gdb-add-index.1
MAN5S = gdbinit.5
MANS = $(MAN1S) $(MAN5S)

# The pod files that are generated as a side effect of creating the
# man pages.
POD_FILE_TMPS = $(patsubst %.1,%.pod,$(MAN1S)) \
		$(patsubst %.5,%.pod,$(MAN5S))

HAVE_NATIVE_GCORE_TARGET = 1
HAVE_NATIVE_GCORE_HOST = 
HAVE_GSTACK = 1

###

all: info

info: $(INFO_DEPS)
dvi: $(DVIFILES)
ps: gdb.ps stabs.ps refcard.ps annotate.ps
html: $(HTMLFILES)
pdf: $(PDFFILES)
man: $(MANS)

DOXYGEN = doxygen
doxyedit = sed -e 's,@srcdir\@,$(srcdir),g'

doxy:	doxy/index.html \
	doxy/gdb-api/index.html \
	doxy/gdb-xref/index.html \
	doxy/gdbserver/index.html

doxy/index.html: $(srcdir)/doxy-index.in
	-mkdir -p doxy
	cp $(srcdir)/doxy-index.in doxy/index.html

doxy/gdb-api/index.html: Doxyfile-gdb-api Doxyfile-base
	-mkdir -p doxy
	$(DOXYGEN) Doxyfile-gdb-api

doxy/gdb-xref/index.html: Doxyfile-gdb-xref Doxyfile-base
	-mkdir -p doxy
	$(DOXYGEN) Doxyfile-gdb-xref

doxy/gdbserver/index.html: Doxyfile-gdbserver Doxyfile-base
	-mkdir -p doxy
	$(DOXYGEN) Doxyfile-gdbserver

Doxyfile-base:	$(srcdir)/Doxyfile-base.in 
	$(doxyedit) $(srcdir)/Doxyfile-base.in >Doxyfile-base

Doxyfile-gdb-api:	$(srcdir)/Doxyfile-gdb-api.in 
	$(doxyedit) $(srcdir)/Doxyfile-gdb-api.in >Doxyfile-gdb-api

Doxyfile-gdb-xref:	$(srcdir)/Doxyfile-gdb-xref.in
	$(doxyedit) $(srcdir)/Doxyfile-gdb-xref.in >Doxyfile-gdb-xref

Doxyfile-gdbserver:	$(srcdir)/Doxyfile-gdbserver.in
	$(doxyedit) $(srcdir)/Doxyfile-gdbserver.in >Doxyfile-gdbserver

all-doc: info man dvi ps pdf html
diststuff: info man

install-info: $(INFO_DEPS)
	$(SHELL) $(srcdir)/../../mkinstalldirs $(DESTDIR)$(infodir)
	@list='$(INFO_DEPS)'; \
	for file in $$list; do \
	  if test -f $$file; then d=.; else d=$(srcdir); fi; \
	  for ifile in `cd $$d && echo $$file $$file-[0-9] $$file-[0-9][0-9]`; do \
	    if test -f $$d/$$ifile; then \
	      echo " $(INSTALL_DATA) $$d/$$ifile $(DESTDIR)$(infodir)/$$ifile"; \
	      $(INSTALL_DATA) $$d/$$ifile $(DESTDIR)$(infodir)/$$ifile; \
	    else : ; fi; \
	  done; \
	done
	$(POST_INSTALL)
	@if $(SHELL) -c 'install-info --version | sed 1q | fgrep -s -v -i debian' >/dev/null 2>&1; then \
	  list='$(INFO_DEPS)'; \
	  for file in $$list; do \
	    echo " install-info --info-dir=$(DESTDIR)$(infodir) $(DESTDIR)$(infodir)/$$file";\
	    install-info --info-dir=$(DESTDIR)$(infodir) $(DESTDIR)$(infodir)/$$file || :;\
	  done; \
	else : ; fi

uninstall-info:
	$(PRE_UNINSTALL)
	@if $(SHELL) -c 'install-info --version | sed 1q | fgrep -s -v -i debian' >/dev/null 2>&1; then \
	  ii=yes; \
	else ii=; fi; \
	list='$(INFO_DEPS)'; \
	for file in $$list; do \
	  test -z "$$ii" \
	    || install-info --info-dir=$(DESTDIR)$(infodir) --remove $$file; \
	done
	$(NORMAL_UNINSTALL)
	list='$(INFO_DEPS)'; \
	for file in $$list; do \
	  (cd $(DESTDIR)$(infodir) && rm -f $$file $$file-[0-9] $$file-[0-9][0-9]); \
	done

html__strip_dir = `echo $$p | sed -e 's|^.*/||'`;

install-html: $(HTMLFILES)
	@$(NORMAL_INSTALL)
	test -z "$(htmldir)" || $(mkinstalldirs) "$(DESTDIR)$(htmldir)"
	@list='$(HTMLFILES_INSTALL)'; for p in $$list; do \
	  if test -f "$$p" || test -d "$$p"; then d=""; else d="$(srcdir)/"; fi; \
	  f=$(html__strip_dir) \
	  if test -d "$$d$$p"; then \
	    echo " $(mkinstalldirs) '$(DESTDIR)$(htmldir)/$$f'"; \
	    $(mkinstalldirs) "$(DESTDIR)$(htmldir)/$$f" || exit 1; \
	    echo " $(INSTALL_DATA) '$$d$$p'/* '$(DESTDIR)$(htmldir)/$$f'"; \
	    $(INSTALL_DATA) "$$d$$p"/* "$(DESTDIR)$(htmldir)/$$f"; \
	  else \
	    echo " $(INSTALL_DATA) '$$d$$p' '$(DESTDIR)$(htmldir)/$$f'"; \
	    $(INSTALL_DATA) "$$d$$p" "$(DESTDIR)$(htmldir)/$$f"; \
	  fi; \
	done

dvi__strip_dir = `echo $$p | sed -e 's|^.*/||'`;

install-dvi: $(DVIFILES)
	@$(NORMAL_INSTALL)
	test -z "$(dvidir)" || $(mkinstalldirs) "$(DESTDIR)$(dvidir)"
	@list='$(DVIFILES)'; for p in $$list; do \
	  if test -f "$$p"; then d=; else d="$(srcdir)/"; fi; \
	  f=$(dvi__strip_dir) \
	  echo " $(INSTALL_DATA) '$$d$$p' '$(DESTDIR)$(dvidir)/$$f'"; \
	  $(INSTALL_DATA) "$$d$$p" "$(DESTDIR)$(dvidir)/$$f"; \
	done

pdf__strip_dir = `echo $$p | sed -e 's|^.*/||'`;

install-pdf: $(PDFFILES)
	@$(NORMAL_INSTALL)
	test -z "$(pdfdir)" || $(mkinstalldirs) "$(DESTDIR)$(pdfdir)"
	@list='$(PDFFILES)'; for p in $$list; do \
	  if test -f "$$p"; then d=; else d="$(srcdir)/"; fi; \
	  f=$(pdf__strip_dir) \
	  echo " $(INSTALL_DATA) '$$d$$p' '$(DESTDIR)$(pdfdir)/$$f'"; \
	  $(INSTALL_DATA) "$$d$$p" "$(DESTDIR)$(pdfdir)/$$f"; \
	done

install-man: install-man1 install-man5

install-man1: $(MAN1S)
	test -z "$(man1dir)" || $(mkinstalldirs) "$(DESTDIR)$(man1dir)"
	@list='$(MAN1S)'; for p in $$list; do \
	  if test "x$(HAVE_NATIVE_GCORE_TARGET)$(HAVE_NATIVE_GCORE_HOST)" = x \
		  -a "$$p" = gcore.1; then \
	    continue; \
	  fi; \
	  if test "x$(HAVE_GSTACK)" = x \
		  -a "$$p" = gstack.1; then \
	    continue; \
	  fi; \
	  if test -f "$$p"; then d=; else d="$(srcdir)/"; fi; \
	  f=`echo $$p | sed -e 's|^.*/||' -e '$(transform)'`; \
	  echo " $(INSTALL_DATA) '$$d$$p' '$(DESTDIR)$(man1dir)/$$f'"; \
	  $(INSTALL_DATA) "$$d$$p" "$(DESTDIR)$(man1dir)/$$f"; \
	done

install-man5: $(MAN5S)
	test -z "$(man5dir)" || $(mkinstalldirs) "$(DESTDIR)$(man5dir)"
	@list='$(MAN5S)'; for p in $$list; do \
	  if test -f "$$p"; then d=; else d="$(srcdir)/"; fi; \
	  f=`echo $$p | sed -e 's|^.*/||' -e '$(transform)'`; \
	  echo " $(INSTALL_DATA) '$$d$$p' '$(DESTDIR)$(man5dir)/$$f'"; \
	  $(INSTALL_DATA) "$$d$$p" "$(DESTDIR)$(man5dir)/$$f"; \
	done

uninstall-man: uninstall-man1 uninstall-man5

uninstall-man1:
	@test -n "$(man1dir)" || exit 0; \
	files=`{ l2='$(MAN1S)'; for i in $$l2; do \
	  if test "x$(HAVE_NATIVE_GCORE_TARGET)$(HAVE_NATIVE_GCORE_HOST)" = x \
		  -a "$$i" = gcore.1; then \
	    continue; \
	  fi; \
	  if test "x$(HAVE_GSTACK)" = x \
		  -a "$$i" = gstack.1; then \
	    continue; \
	  fi; \
	  echo "$$i"; \
	done | \
	  sed -n '/\.1[a-z]*$$/p'; \
	} | sed -e 's,.*/,,;h;s,.*\.,,;s,^[^1][0-9a-z]*$$,1,;x' \
	      -e 's,\.[0-9a-z]*$$,,;$(transform);G;s,\n,.,'`; \
	test -z "$$files" || { \
	  echo " ( cd '$(DESTDIR)$(man1dir)' && rm -f" $$files ")"; \
	  cd "$(DESTDIR)$(man1dir)" && rm -f $$files; }

uninstall-man5:
	@test -n "$(man5dir)" || exit 0; \
	files=`{ l2='$(MAN5S)'; for i in $$l2; do echo "$$i"; done | \
	  sed -n '/\.5[a-z]*$$/p'; \
	} | sed -e 's,.*/,,;h;s,.*\.,,;s,^[^5][0-9a-z]*$$,5,;x' \
	      -e 's,\.[0-9a-z]*$$,,;$(transform);G;s,\n,.,'`; \
	test -z "$$files" || { \
	  echo " ( cd '$(DESTDIR)$(man5dir)' && rm -f" $$files ")"; \
	  cd "$(DESTDIR)$(man5dir)" && rm -f $$files; }

STAGESTUFF = *.info* gdb-all.texi GDBvn.texi *.ps *.dvi *.pdf *.1 *.5

# Copy the object files from a particular stage into a subdirectory.
stage1: force
	-mkdir stage1
	-mv $(STAGESTUFF) stage1

stage2: force
	-mkdir stage2
	-mv $(STAGESTUFF) stage2

stage3: force
	-mkdir stage3
	-mv $(STAGESTUFF) stage3

against=stage2

comparison: force
	for i in $(STAGESTUFF) ; do cmp $$i $(against)/$$i ; done

de-stage1: force
	-(cd stage1 ; mv -f * ..)
	-rmdir stage1

de-stage2: force
	-(cd stage2 ; mv -f * ..)
	-rmdir stage2

de-stage3: force
	-(cd stage3 ; mv -f * ..)
	-rmdir stage3


sedref.tex : refcard.tex $(REFEDITS)
	$(SILENCE) echo > refcard.sed
	$(SILENCE) for f in x $(REFEDITS) ; do \
		test x$$f = xx && continue ; \
		cat $(srcdir)/$$f >>refcard.sed ; \
	done
	$(ECHO_GEN) sed -f refcard.sed $(srcdir)/refcard.tex >$@
	$(SILENCE) rm -f refcard.sed


# GDB QUICK REFERENCE (dvi output)
refcard.dvi : sedref.tex
	$(SILENCE) rm -f sedref_dvi.*
	$(SILENCE) cp $< sedref_dvi.tex
	$(ECHO_TEX) $(SET_TEXINPUTS) $(TEX) sedref_dvi.tex && \
		mv sedref_dvi.dvi $@

refcard.ps : refcard.dvi
	$(ECHO_DVIPS) $(DVIPS) $(SILENT_Q_FLAG) -t landscape -o $@ $?

refcard.pdf : sedref.tex
	$(SILENCE) rm -f sedref_pdf.*
	$(SILENCE) cp $< sedref_pdf.tex
	$(ECHO_PDFTEX) $(SET_TEXINPUTS) $(PDFTEX) sedref_pdf.tex && \
		mv sedref_pdf.pdf $@

# File to record current GDB version number.
#
# It is important that version.subst be the first dependency so that
# $< can be used in the recipe, this allows us to find version.subst
# in either the source tree or the build tree as this file is
# included, pre-built, as part of a release.
GDBvn.texi : version.subst
	$(ECHO_GEN)
	$(SILENCE) echo "@set GDBVN `sed q $<`" > ./GDBvn.new
	$(SILENCE) if [ -n "$(PKGVERSION)" ]; then \
	  echo "@set VERSION_PACKAGE $(PKGVERSION)" >> ./GDBvn.new; \
	fi
	$(SILENCE) echo "@set BUGURL $(BUGURL_TEXI)" >> ./GDBvn.new
	$(SILENCE) if [ "$(BUGURL_TEXI)" = "@uref{http://www.gnu.org/software/gdb/bugs/}" ]; then \
	  echo "@set BUGURL_DEFAULT" >> ./GDBvn.new; \
	fi
	$(SILENCE) if test -z "$(READLINE_TEXI_INCFLAG)"; then \
	  echo "@set SYSTEM_READLINE" >> ./GDBvn.new; \
	fi
	$(SILENCE) if [ -n "$(SYSTEM_GDBINIT)" ]; then \
	  escaped_system_gdbinit=`echo $(SYSTEM_GDBINIT) | sed 's/@/@@/g'`; \
	  echo "@set SYSTEM_GDBINIT $$escaped_system_gdbinit" >> ./GDBvn.new; \
	fi
	$(SILENCE) if [ -n "$(SYSTEM_GDBINIT_DIR)" ]; then \
	  escaped_system_gdbinit_dir=`echo $(SYSTEM_GDBINIT_DIR) | sed 's/@/@@/g'`; \
	  echo "@set SYSTEM_GDBINIT_DIR $$escaped_system_gdbinit_dir" >> ./GDBvn.new; \
	fi
	$(SILENCE) mv GDBvn.new GDBvn.texi

version.subst: $(gdbdir)/version.in $(gdbdir)/../bfd/version.h
	$(ECHO_GEN) date=`sed -n -e 's/^.* BFD_VERSION_DATE \(.*\)$$/\1/p' $(gdbdir)/../bfd/version.h`; \
	sed -e "s/DATE/$$date/" < $(gdbdir)/version.in > version.subst

# Updated atomically
.PRECIOUS: GDBvn.texi

# Choose configuration for GDB manual (normally `all'; normally not tied into
# `configure' script because most users prefer generic version of manual,
# not one for their binary config---which may not be specifically
# defined anyways).
gdb-cfg.texi: ${srcdir}/${DOC_CONFIG}-cfg.texi
	$(ECHO_GEN) (test "$(LN_S)" = "ln -s" && \
	  ln -s ${srcdir}/${DOC_CONFIG}-cfg.texi gdb-cfg.texi) || \
	ln ${srcdir}/${DOC_CONFIG}-cfg.texi gdb-cfg.texi || \
	cp ${srcdir}/${DOC_CONFIG}-cfg.texi gdb-cfg.texi

# GDB MANUAL: TeX dvi file
gdb.dvi: ${GDB_DOC_FILES}
	$(ECHO_TEXI2DVI) $(TEXI2DVI_CMD) $(SILENT_Q_FLAG) \
		$(READLINE_TEXI_INCFLAG) -I ${GDBMI_DIR} -I $(srcdir) \
		$(srcdir)/gdb.texinfo

gdb.ps: gdb.dvi
	$(ECHO_DVIPS) $(DVIPS) $(SILENT_Q_FLAG) -o $@ $?

gdb.pdf: ${GDB_DOC_FILES}
	$(ECHO_TEXI2DVI) $(TEXI2DVI_CMD) $(SILENT_Q_FLAG) --pdf \
		$(READLINE_TEXI_INCFLAG) -I ${GDBMI_DIR} -I $(srcdir) \
		$(srcdir)/gdb.texinfo

# GDB MANUAL: info file
gdb.info: ${GDB_DOC_FILES}
	$(ECHO_MAKEINFO) $(MAKEINFO_CMD) $(READLINE_TEXI_INCFLAG) -I ${GDBMI_DIR} -I $(srcdir) \
		-o gdb.info $(srcdir)/gdb.texinfo

# GDB MANUAL: roff translations
# Try to use a recent texi2roff.  v2 was put on prep in jan91.
# If you want an index, see texi2roff doc for postprocessing 
# and add -i to texi2roff invocations below.
# Workarounds for texi2roff-2 (probably fixed in later texi2roff's, delete
#    corresponding -e lines when later texi2roff's are current)
# + @ifinfo's deleted explicitly due to texi2roff-2 bug w nested constructs.
# + @c's deleted explicitly because texi2roff sees texinfo commands in them
# + @   (that's at-BLANK) not recognized by texi2roff, turned into blank
# + @alphaenumerate is ridiculously new, turned into @enumerate

# texi2roff doesn't have a notion of include dirs, so we have to fake 
# it out for gdb manual's include files---but only if not configured
# in main sourcedir.
links2roff: $(GDB_DOC_SOURCE_INCLUDES)
	$(ECHO_GEN) if [ ! -f gdb.texinfo ]; then \
		(test "$(LN_S)" = "ln -s" && ln -s $(GDB_DOC_SOURCE_INCLUDES) .) || \
		ln $(GDB_DOC_SOURCE_INCLUDES)    . || \
		cp $(GDB_DOC_SOURCE_INCLUDES)    . ; \
	fi
	$(SILENCE) touch links2roff

# gdb manual suitable for [gtn]roff -me
gdb.me: $(GDB_DOC_FILES) links2roff
	$(ECHO_GEN) sed -e '/\\input texinfo/d' \
		-e '/@c TEXI2ROFF-KILL/,/@c END TEXI2ROFF-KILL/d' \
		-e '/^@ifinfo/,/^@end ifinfo/d' \
		-e '/^@c /d' \
		-e 's/{.*,,/{/' \
		-e 's/@ / /g' \
		-e 's/^@alphaenumerate/@enumerate/g' \
		-e 's/^@end alphaenumerate/@end enumerate/g' \
		$(srcdir)/gdb.texinfo | \
	$(TEXI2ROFF) -me | \
	sed -e 's/---/\\(em/g' \
	>gdb.me 

# gdb manual suitable for [gtn]roff -ms
gdb.ms: $(GDB_DOC_FILES) links2roff
	$(ECHO_GEN) sed -e '/\\input texinfo/d' \
		-e '/@c TEXI2ROFF-KILL/,/@c END TEXI2ROFF-KILL/d' \
		-e '/^@ifinfo/,/^@end ifinfo/d' \
		-e '/^@c /d' \
		-e 's/{.*,,/{/' \
		-e 's/@ / /g' \
		-e 's/^@alphaenumerate/@enumerate/g' \
		-e 's/^@end alphaenumerate/@end enumerate/g' \
		$(srcdir)/gdb.texinfo | \
	$(TEXI2ROFF) -ms | \
	sed -e 's/---/\\(em/g' \
	>gdb.ms 

# gdb manual suitable for [tn]roff -mm
# '@noindent's removed due to texi2roff-2 mm bug; if yours is newer, 
#   try leaving them in
gdb.mm: $(GDB_DOC_FILES) links2roff
	$(ECHO_GEN) sed -e '/\\input texinfo/d' \
		-e '/@c TEXI2ROFF-KILL/,/@c END TEXI2ROFF-KILL/d' \
		-e '/^@ifinfo/,/^@end ifinfo/d' \
		-e '/^@c /d' \
		-e 's/{.*,,/{/' \
		-e '/@noindent/d' \
		-e 's/@ / /g' \
		-e 's/^@alphaenumerate/@enumerate/g' \
		-e 's/^@end alphaenumerate/@end enumerate/g' \
		$(srcdir)/gdb.texinfo | \
	$(TEXI2ROFF) -mm | \
	sed -e 's/---/\\(em/g' \
	>gdb.mm 

# GDB MANUAL: HTML file

gdb/index.html: ${GDB_DOC_FILES}
	$(ECHO_GEN) $(MAKEHTML) $(MAKEHTMLFLAGS) \
		-o gdb \
		$(READLINE_TEXI_INCFLAG) -I ${GDBMI_DIR} -I $(srcdir) \
		$(srcdir)/gdb.texinfo

stabs.info: $(STABS_DOC_FILES)
	$(ECHO_MAKEINFO) $(MAKEINFO_CMD) -I $(srcdir) -o stabs.info $(srcdir)/stabs.texinfo

# STABS DOCUMENTATION: HTML file

stabs/index.html: $(STABS_DOC_FILES)
	$(ECHO_GEN) $(MAKEHTML) $(MAKEHTMLFLAGS) \
		-o stabs \
		-I $(srcdir) \
		$(srcdir)/stabs.texinfo

# STABS DOCUMENTATION: TeX dvi file
stabs.dvi : $(STABS_DOC_FILES)
	$(ECHO_TEXI2DVI) $(TEXI2DVI_CMD) $(SILENT_Q_FLAG) -I $(srcdir) \
		$(srcdir)/stabs.texinfo

stabs.ps: stabs.dvi
	$(ECHO_DVIPS) $(DVIPS) $(SILENT_Q_FLAG) -o $@ $?

stabs.pdf: $(STABS_DOC_FILES)
	$(ECHO_TEXI2DVI) $(TEXI2DVI_CMD) $(SILENT_Q_FLAG) --pdf -I $(srcdir) \
		$(srcdir)/stabs.texinfo

# ANNOTATE DOCUMENTATION: TeX dvi file
annotate.dvi : $(ANNOTATE_DOC_FILES)
	$(ECHO_TEXI2DVI) $(TEXI2DVI_CMD) $(SILENT_Q_FLAG) -I $(srcdir) \
		$(srcdir)/annotate.texinfo

annotate.ps: annotate.dvi
	$(ECHO_DVIPS) $(DVIPS) $(SILENT_Q_FLAG) -o $@ $?

annotate.pdf: $(ANNOTATE_DOC_FILES)
	$(ECHO_TEXI2DVI) $(TEXI2DVI_CMD) $(SILENT_Q_FLAG) --pdf -I $(srcdir) \
		$(srcdir)/annotate.texinfo

annotate.info: $(ANNOTATE_DOC_FILES)
	$(ECHO_MAKEINFO) $(MAKEINFO_CMD) -I $(srcdir) -o annotate.info $(srcdir)/annotate.texinfo

annotate/index.html: $(ANNOTATE_DOC_FILES)
	$(ECHO_MAKEHTML) $(MAKEHTML) $(MAKEHTMLFLAGS) \
		-o annotate \
		-I $(srcdir) \
		$(srcdir)/annotate.texinfo

# Man pages.  The TEXI2POD and TEXI2MAN steps are performed within a
# single recipe to support how we distribute GDB releases.  A release
# includes the .1 and .5 man pages in the source tree, but not the
# .pod files.
#
# When building and installing a release of GDB it should not be
# necessary to rebuild the .1 or .5 man page files, nor should it be
# necessary to rebuild the .pod files.
#
# If we split the .pod creation from the creation of the .1 and .5
# pages, then the .pod files must become a dependency, this will
# trigger an attempt to rebuild these files while building and
# installing a release of GDB, which is something we don't want.
#
# It is important that version.subst be the first dependency so that
# $< can be used in the recipe, this allows us to find version.subst
# in either the source tree or the build tree as this file is
# included, pre-built, as part of a release.
$(MAN1S) $(MAN5S) : version.subst $(GDB_DOC_FILES)
	$(ECHO_TEXI2POD) $(TEXI2POD) $(MANCONF) -D$(basename $@) \
		< $(srcdir)/gdb.texinfo > $(basename $@).pod
	$(ECHO_TEXI2MAN) ($(POD2MAN) --section=$(subst .,,$(suffix $@)) \
			--release="gdb-`sed q $<`" $(basename $@).pod | \
		sed -e '/^.if n .na/d' > $@.T$$$$ && \
		mv -f $@.T$$$$ $@) || (rm -f $@.T$$$$ && exit 1)
	$(SILENCE) rm -f $(basename $@).pod

force:

Makefile: Makefile.in $(host_makefile_frag) ../config.status
	$(ECHO_GEN) cd .. && $(SHELL) ./config.status $(SILENT_FLAG) doc/Makefile


# The "least clean" level of cleaning.  Get rid of files which are
# automatically generated files that are just intermediate files,

mostlyclean:
	rm -f gdb.mm gdb.ms gdb.me links2roff
	rm -fr $(TEXI2DVI_TMPDIR)
	rm -f refcard.sed sedref.tex sedref_dvi.* sedref_pdf.*
	rm -f $(POD_FILE_TMPS)

clean: mostlyclean
	rm -f gdb-cfg.texi

distclean: clean
	rm -f Makefile

# GDBvn.texi, the dvi files, the info files, and the postscript files, 
# are all part of the distribution, so it should not be removed by
# "clean" or "distclean".  Use maintainer-clean to remove them.

maintainer-clean realclean: distclean
	rm -f GDBvn.texi version.subst *.info* *.dvi *.ps *.html *.pdf $(MANS)

install: install-info install-man

uninstall: uninstall-info uninstall-man

# Disable implicit make rules.
include $(srcdir)/../disable-implicit-rules.mk
