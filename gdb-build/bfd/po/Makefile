# Makefile for program source directory in GNU NLS utilities package.
# Copyright (C) 1995, 1996, 1997 by Ulrich Drepper <drepper@gnu.ai.mit.edu>
# Copyright (C) 2001-2025 Free Software Foundation, Inc.
#
# This file may be copied and used freely without restrictions.  It can
# be used in projects which are not available under the GNU Public License
# but which still want to provide support for the GNU gettext functionality.
# Please note that the actual code is *not* freely available.

PACKAGE = bfd
VERSION = 2.45.50

SHELL = /bin/sh


srcdir = ../../../binutils-gdb/bfd/po
top_srcdir = ../../../binutils-gdb/bfd
VPATH = ../../../binutils-gdb/bfd/po
top_builddir = ..

prefix = /usr/local
exec_prefix = ${prefix}
datadir = ${datarootdir}
localedir = ${datarootdir}/locale
gnulocaledir = ${prefix}/share/locale
gettextsrcdir = ${prefix}/share/gettext/po
subdir = po

DESTDIR =

INSTALL = /usr/bin/install -c
INSTALL_DATA = /usr/bin/install -c -m 644
MKINSTALLDIRS = $(top_builddir)/../../binutils-gdb/bfd/../mkinstalldirs

CC = gcc
GENCAT = 
GMSGFMT = PATH=../src:$$PATH :
MSGFMT = :
XGETTEXT = PATH=../src:$$PATH :
MSGMERGE = PATH=../src:$$PATH msgmerge

DEFS = -DHAVE_CONFIG_H
CFLAGS = -g -O2    
CPPFLAGS = 

INCLUDES = -I.. -I$(top_srcdir)/intl

COMPILE = $(CC) -c $(DEFS) $(INCLUDES) $(CPPFLAGS) $(CFLAGS) $(XCFLAGS)

SOURCES = cat-id-tbl.c
POFILES =  $(srcdir)/da.po $(srcdir)/es.po $(srcdir)/fi.po $(srcdir)/fr.po $(srcdir)/hr.po $(srcdir)/id.po $(srcdir)/ja.po $(srcdir)/ro.po $(srcdir)/ru.po $(srcdir)/rw.po $(srcdir)/sr.po $(srcdir)/sv.po $(srcdir)/tr.po $(srcdir)/uk.po $(srcdir)/vi.po $(srcdir)/zh_CN.po $(srcdir)/pt.po
GMOFILES =  $(srcdir)/da.gmo $(srcdir)/es.gmo $(srcdir)/fi.gmo $(srcdir)/fr.gmo $(srcdir)/hr.gmo $(srcdir)/id.gmo $(srcdir)/ja.gmo $(srcdir)/ro.gmo $(srcdir)/ru.gmo $(srcdir)/rw.gmo $(srcdir)/sr.gmo $(srcdir)/sv.gmo $(srcdir)/tr.gmo $(srcdir)/uk.gmo $(srcdir)/vi.gmo $(srcdir)/zh_CN.gmo $(srcdir)/pt.gmo
DISTFILES = ChangeLog Makefile.in.in SRC-POTFILES.in BLD-POTFILES.in $(PACKAGE).pot \
stamp-cat-id $(POFILES) $(GMOFILES) $(SOURCES)

# Note - the following line gets processed by bfd/configure and amended
# to contain the full list of source dir POTFILES.
SRC-POTFILES = \
	../../../binutils-gdb/bfd/aix5ppc-core.c \
	../../../binutils-gdb/bfd/aout-cris.c \
	../../../binutils-gdb/bfd/aout-ns32k.c \
	../../../binutils-gdb/bfd/aout-target.h \
	../../../binutils-gdb/bfd/aout32.c \
	../../../binutils-gdb/bfd/aout64.c \
	../../../binutils-gdb/bfd/aoutx.h \
	../../../binutils-gdb/bfd/arc-got.h \
	../../../binutils-gdb/bfd/arc-plt.h \
	../../../binutils-gdb/bfd/archive.c \
	../../../binutils-gdb/bfd/archive64.c \
	../../../binutils-gdb/bfd/archures.c \
	../../../binutils-gdb/bfd/bfd.c \
	../../../binutils-gdb/bfd/bfdio.c \
	../../../binutils-gdb/bfd/binary.c \
	../../../binutils-gdb/bfd/cache.c \
	../../../binutils-gdb/bfd/cf-i386lynx.c \
	../../../binutils-gdb/bfd/cisco-core.c \
	../../../binutils-gdb/bfd/coff-alpha.c \
	../../../binutils-gdb/bfd/coff-arm.h \
	../../../binutils-gdb/bfd/coff-bfd.c \
	../../../binutils-gdb/bfd/coff-bfd.h \
	../../../binutils-gdb/bfd/coff-go32.c \
	../../../binutils-gdb/bfd/coff-i386.c \
	../../../binutils-gdb/bfd/coff-mips.c \
	../../../binutils-gdb/bfd/coff-rs6000.c \
	../../../binutils-gdb/bfd/coff-sh.c \
	../../../binutils-gdb/bfd/coff-stgo32.c \
	../../../binutils-gdb/bfd/coff-tic30.c \
	../../../binutils-gdb/bfd/coff-tic4x.c \
	../../../binutils-gdb/bfd/coff-tic54x.c \
	../../../binutils-gdb/bfd/coff-x86_64.c \
	../../../binutils-gdb/bfd/coff-z80.c \
	../../../binutils-gdb/bfd/coff-z8k.c \
	../../../binutils-gdb/bfd/coff64-rs6000.c \
	../../../binutils-gdb/bfd/coffcode.h \
	../../../binutils-gdb/bfd/coffgen.c \
	../../../binutils-gdb/bfd/cofflink.c \
	../../../binutils-gdb/bfd/coffswap.h \
	../../../binutils-gdb/bfd/compress.c \
	../../../binutils-gdb/bfd/corefile.c \
	../../../binutils-gdb/bfd/cpu-aarch64.c \
	../../../binutils-gdb/bfd/cpu-aarch64.h \
	../../../binutils-gdb/bfd/cpu-alpha.c \
	../../../binutils-gdb/bfd/cpu-amdgcn.c \
	../../../binutils-gdb/bfd/cpu-arc.c \
	../../../binutils-gdb/bfd/cpu-arm.c \
	../../../binutils-gdb/bfd/cpu-arm.h \
	../../../binutils-gdb/bfd/cpu-avr.c \
	../../../binutils-gdb/bfd/cpu-bfin.c \
	../../../binutils-gdb/bfd/cpu-bpf.c \
	../../../binutils-gdb/bfd/cpu-cr16.c \
	../../../binutils-gdb/bfd/cpu-cris.c \
	../../../binutils-gdb/bfd/cpu-crx.c \
	../../../binutils-gdb/bfd/cpu-csky.c \
	../../../binutils-gdb/bfd/cpu-d10v.c \
	../../../binutils-gdb/bfd/cpu-d30v.c \
	../../../binutils-gdb/bfd/cpu-dlx.c \
	../../../binutils-gdb/bfd/cpu-epiphany.c \
	../../../binutils-gdb/bfd/cpu-fr30.c \
	../../../binutils-gdb/bfd/cpu-frv.c \
	../../../binutils-gdb/bfd/cpu-ft32.c \
	../../../binutils-gdb/bfd/cpu-h8300.c \
	../../../binutils-gdb/bfd/cpu-h8300.h \
	../../../binutils-gdb/bfd/cpu-hppa.c \
	../../../binutils-gdb/bfd/cpu-i386.c \
	../../../binutils-gdb/bfd/cpu-ia64.c \
	../../../binutils-gdb/bfd/cpu-iamcu.c \
	../../../binutils-gdb/bfd/cpu-ip2k.c \
	../../../binutils-gdb/bfd/cpu-iq2000.c \
	../../../binutils-gdb/bfd/cpu-kvx.c \
	../../../binutils-gdb/bfd/cpu-lm32.c \
	../../../binutils-gdb/bfd/cpu-loongarch.c \
	../../../binutils-gdb/bfd/cpu-m10200.c \
	../../../binutils-gdb/bfd/cpu-m10300.c \
	../../../binutils-gdb/bfd/cpu-m32c.c \
	../../../binutils-gdb/bfd/cpu-m32r.c \
	../../../binutils-gdb/bfd/cpu-m68hc11.c \
	../../../binutils-gdb/bfd/cpu-m68hc12.c \
	../../../binutils-gdb/bfd/cpu-m68k.c \
	../../../binutils-gdb/bfd/cpu-m68k.h \
	../../../binutils-gdb/bfd/cpu-m9s12x.c \
	../../../binutils-gdb/bfd/cpu-m9s12xg.c \
	../../../binutils-gdb/bfd/cpu-mcore.c \
	../../../binutils-gdb/bfd/cpu-mep.c \
	../../../binutils-gdb/bfd/cpu-metag.c \
	../../../binutils-gdb/bfd/cpu-microblaze.c \
	../../../binutils-gdb/bfd/cpu-mips.c \
	../../../binutils-gdb/bfd/cpu-mmix.c \
	../../../binutils-gdb/bfd/cpu-moxie.c \
	../../../binutils-gdb/bfd/cpu-msp430.c \
	../../../binutils-gdb/bfd/cpu-mt.c \
	../../../binutils-gdb/bfd/cpu-nds32.c \
	../../../binutils-gdb/bfd/cpu-nfp.c \
	../../../binutils-gdb/bfd/cpu-ns32k.c \
	../../../binutils-gdb/bfd/cpu-or1k.c \
	../../../binutils-gdb/bfd/cpu-pdp11.c \
	../../../binutils-gdb/bfd/cpu-pj.c \
	../../../binutils-gdb/bfd/cpu-powerpc.c \
	../../../binutils-gdb/bfd/cpu-pru.c \
	../../../binutils-gdb/bfd/cpu-riscv.c \
	../../../binutils-gdb/bfd/cpu-riscv.h \
	../../../binutils-gdb/bfd/cpu-rl78.c \
	../../../binutils-gdb/bfd/cpu-rs6000.c \
	../../../binutils-gdb/bfd/cpu-rx.c \
	../../../binutils-gdb/bfd/cpu-s12z.c \
	../../../binutils-gdb/bfd/cpu-s390.c \
	../../../binutils-gdb/bfd/cpu-score.c \
	../../../binutils-gdb/bfd/cpu-sh.c \
	../../../binutils-gdb/bfd/cpu-sparc.c \
	../../../binutils-gdb/bfd/cpu-spu.c \
	../../../binutils-gdb/bfd/cpu-tic30.c \
	../../../binutils-gdb/bfd/cpu-tic4x.c \
	../../../binutils-gdb/bfd/cpu-tic54x.c \
	../../../binutils-gdb/bfd/cpu-tic6x.c \
	../../../binutils-gdb/bfd/cpu-tilegx.c \
	../../../binutils-gdb/bfd/cpu-tilepro.c \
	../../../binutils-gdb/bfd/cpu-v850.c \
	../../../binutils-gdb/bfd/cpu-v850_rh850.c \
	../../../binutils-gdb/bfd/cpu-vax.c \
	../../../binutils-gdb/bfd/cpu-visium.c \
	../../../binutils-gdb/bfd/cpu-wasm32.c \
	../../../binutils-gdb/bfd/cpu-xgate.c \
	../../../binutils-gdb/bfd/cpu-xstormy16.c \
	../../../binutils-gdb/bfd/cpu-xtensa.c \
	../../../binutils-gdb/bfd/cpu-z80.c \
	../../../binutils-gdb/bfd/cpu-z8k.c \
	../../../binutils-gdb/bfd/dwarf1.c \
	../../../binutils-gdb/bfd/dwarf2.c \
	../../../binutils-gdb/bfd/ecoff-bfd.h \
	../../../binutils-gdb/bfd/ecoff.c \
	../../../binutils-gdb/bfd/ecofflink.c \
	../../../binutils-gdb/bfd/ecoffswap.h \
	../../../binutils-gdb/bfd/elf-attrs.c \
	../../../binutils-gdb/bfd/elf-bfd.h \
	../../../binutils-gdb/bfd/elf-eh-frame.c \
	../../../binutils-gdb/bfd/elf-hppa.h \
	../../../binutils-gdb/bfd/elf-ifunc.c \
	../../../binutils-gdb/bfd/elf-linker-x86.h \
	../../../binutils-gdb/bfd/elf-linux-core.h \
	../../../binutils-gdb/bfd/elf-m10200.c \
	../../../binutils-gdb/bfd/elf-m10300.c \
	../../../binutils-gdb/bfd/elf-properties.c \
	../../../binutils-gdb/bfd/elf-s390.h \
	../../../binutils-gdb/bfd/elf-sframe.c \
	../../../binutils-gdb/bfd/elf-strtab.c \
	../../../binutils-gdb/bfd/elf-vxworks.c \
	../../../binutils-gdb/bfd/elf-vxworks.h \
	../../../binutils-gdb/bfd/elf.c \
	../../../binutils-gdb/bfd/elf32-am33lin.c \
	../../../binutils-gdb/bfd/elf32-arc.c \
	../../../binutils-gdb/bfd/elf32-arm.c \
	../../../binutils-gdb/bfd/elf32-arm.h \
	../../../binutils-gdb/bfd/elf32-avr.c \
	../../../binutils-gdb/bfd/elf32-avr.h \
	../../../binutils-gdb/bfd/elf32-bfin.c \
	../../../binutils-gdb/bfd/elf32-bfin.h \
	../../../binutils-gdb/bfd/elf32-cr16.c \
	../../../binutils-gdb/bfd/elf32-cr16.h \
	../../../binutils-gdb/bfd/elf32-cris.c \
	../../../binutils-gdb/bfd/elf32-crx.c \
	../../../binutils-gdb/bfd/elf32-csky.c \
	../../../binutils-gdb/bfd/elf32-csky.h \
	../../../binutils-gdb/bfd/elf32-d10v.c \
	../../../binutils-gdb/bfd/elf32-d30v.c \
	../../../binutils-gdb/bfd/elf32-dlx.c \
	../../../binutils-gdb/bfd/elf32-dlx.h \
	../../../binutils-gdb/bfd/elf32-epiphany.c \
	../../../binutils-gdb/bfd/elf32-fr30.c \
	../../../binutils-gdb/bfd/elf32-frv.c \
	../../../binutils-gdb/bfd/elf32-ft32.c \
	../../../binutils-gdb/bfd/elf32-gen.c \
	../../../binutils-gdb/bfd/elf32-h8300.c \
	../../../binutils-gdb/bfd/elf32-hppa.c \
	../../../binutils-gdb/bfd/elf32-hppa.h \
	../../../binutils-gdb/bfd/elf32-i386.c \
	../../../binutils-gdb/bfd/elf32-ip2k.c \
	../../../binutils-gdb/bfd/elf32-iq2000.c \
	../../../binutils-gdb/bfd/elf32-lm32.c \
	../../../binutils-gdb/bfd/elf32-m32c.c \
	../../../binutils-gdb/bfd/elf32-m32r.c \
	../../../binutils-gdb/bfd/elf32-m68hc11.c \
	../../../binutils-gdb/bfd/elf32-m68hc12.c \
	../../../binutils-gdb/bfd/elf32-m68hc1x.c \
	../../../binutils-gdb/bfd/elf32-m68hc1x.h \
	../../../binutils-gdb/bfd/elf32-m68k.c \
	../../../binutils-gdb/bfd/elf32-m68k.h \
	../../../binutils-gdb/bfd/elf32-mcore.c \
	../../../binutils-gdb/bfd/elf32-mep.c \
	../../../binutils-gdb/bfd/elf32-metag.c \
	../../../binutils-gdb/bfd/elf32-metag.h \
	../../../binutils-gdb/bfd/elf32-microblaze.c \
	../../../binutils-gdb/bfd/elf32-mips.c \
	../../../binutils-gdb/bfd/elf32-moxie.c \
	../../../binutils-gdb/bfd/elf32-msp430.c \
	../../../binutils-gdb/bfd/elf32-mt.c \
	../../../binutils-gdb/bfd/elf32-nds32.c \
	../../../binutils-gdb/bfd/elf32-nds32.h \
	../../../binutils-gdb/bfd/elf32-or1k.c \
	../../../binutils-gdb/bfd/elf32-pj.c \
	../../../binutils-gdb/bfd/elf32-ppc.c \
	../../../binutils-gdb/bfd/elf32-ppc.h \
	../../../binutils-gdb/bfd/elf32-pru.c \
	../../../binutils-gdb/bfd/elf32-rl78.c \
	../../../binutils-gdb/bfd/elf32-rx.c \
	../../../binutils-gdb/bfd/elf32-rx.h \
	../../../binutils-gdb/bfd/elf32-s12z.c \
	../../../binutils-gdb/bfd/elf32-s390.c \
	../../../binutils-gdb/bfd/elf32-score.c \
	../../../binutils-gdb/bfd/elf32-score.h \
	../../../binutils-gdb/bfd/elf32-score7.c \
	../../../binutils-gdb/bfd/elf32-sh-relocs.h \
	../../../binutils-gdb/bfd/elf32-sh.c \
	../../../binutils-gdb/bfd/elf32-sparc.c \
	../../../binutils-gdb/bfd/elf32-spu.c \
	../../../binutils-gdb/bfd/elf32-spu.h \
	../../../binutils-gdb/bfd/elf32-tic6x.c \
	../../../binutils-gdb/bfd/elf32-tic6x.h \
	../../../binutils-gdb/bfd/elf32-tilegx.c \
	../../../binutils-gdb/bfd/elf32-tilegx.h \
	../../../binutils-gdb/bfd/elf32-tilepro.c \
	../../../binutils-gdb/bfd/elf32-tilepro.h \
	../../../binutils-gdb/bfd/elf32-v850.c \
	../../../binutils-gdb/bfd/elf32-v850.h \
	../../../binutils-gdb/bfd/elf32-vax.c \
	../../../binutils-gdb/bfd/elf32-visium.c \
	../../../binutils-gdb/bfd/elf32-wasm32.c \
	../../../binutils-gdb/bfd/elf32-xgate.c \
	../../../binutils-gdb/bfd/elf32-xstormy16.c \
	../../../binutils-gdb/bfd/elf32-xtensa.c \
	../../../binutils-gdb/bfd/elf32-z80.c \
	../../../binutils-gdb/bfd/elf32.c \
	../../../binutils-gdb/bfd/elf64-alpha.c \
	../../../binutils-gdb/bfd/elf64-amdgcn.c \
	../../../binutils-gdb/bfd/elf64-bpf.c \
	../../../binutils-gdb/bfd/elf64-gen.c \
	../../../binutils-gdb/bfd/elf64-hppa.c \
	../../../binutils-gdb/bfd/elf64-hppa.h \
	../../../binutils-gdb/bfd/elf64-ia64-vms.c \
	../../../binutils-gdb/bfd/elf64-mips.c \
	../../../binutils-gdb/bfd/elf64-mmix.c \
	../../../binutils-gdb/bfd/elf64-nfp.c \
	../../../binutils-gdb/bfd/elf64-ppc.c \
	../../../binutils-gdb/bfd/elf64-ppc.h \
	../../../binutils-gdb/bfd/elf64-s390.c \
	../../../binutils-gdb/bfd/elf64-sparc.c \
	../../../binutils-gdb/bfd/elf64-tilegx.c \
	../../../binutils-gdb/bfd/elf64-tilegx.h \
	../../../binutils-gdb/bfd/elf64-x86-64.c \
	../../../binutils-gdb/bfd/elf64.c \
	../../../binutils-gdb/bfd/elfcode.h \
	../../../binutils-gdb/bfd/elfcore.h \
	../../../binutils-gdb/bfd/elflink.c \
	../../../binutils-gdb/bfd/elfn32-mips.c \
	../../../binutils-gdb/bfd/elfxx-aarch64.c \
	../../../binutils-gdb/bfd/elfxx-aarch64.h \
	../../../binutils-gdb/bfd/elfxx-ia64.c \
	../../../binutils-gdb/bfd/elfxx-ia64.h \
	../../../binutils-gdb/bfd/elfxx-kvx.c \
	../../../binutils-gdb/bfd/elfxx-loongarch.c \
	../../../binutils-gdb/bfd/elfxx-loongarch.h \
	../../../binutils-gdb/bfd/elfxx-mips.c \
	../../../binutils-gdb/bfd/elfxx-mips.h \
	../../../binutils-gdb/bfd/elfxx-riscv.c \
	../../../binutils-gdb/bfd/elfxx-riscv.h \
	../../../binutils-gdb/bfd/elfxx-sparc.c \
	../../../binutils-gdb/bfd/elfxx-sparc.h \
	../../../binutils-gdb/bfd/elfxx-tilegx.c \
	../../../binutils-gdb/bfd/elfxx-tilegx.h \
	../../../binutils-gdb/bfd/elfxx-x86.c \
	../../../binutils-gdb/bfd/elfxx-x86.h \
	../../../binutils-gdb/bfd/format.c \
	../../../binutils-gdb/bfd/genlink.h \
	../../../binutils-gdb/bfd/go32stub.h \
	../../../binutils-gdb/bfd/hash.c \
	../../../binutils-gdb/bfd/hpux-core.c \
	../../../binutils-gdb/bfd/i386aout.c \
	../../../binutils-gdb/bfd/i386bsd.c \
	../../../binutils-gdb/bfd/i386lynx.c \
	../../../binutils-gdb/bfd/i386msdos.c \
	../../../binutils-gdb/bfd/ihex.c \
	../../../binutils-gdb/bfd/irix-core.c \
	../../../binutils-gdb/bfd/libaout.h \
	../../../binutils-gdb/bfd/libbfd.c \
	../../../binutils-gdb/bfd/libbfd.h \
	../../../binutils-gdb/bfd/libcoff.h \
	../../../binutils-gdb/bfd/libecoff.h \
	../../../binutils-gdb/bfd/libhppa.h \
	../../../binutils-gdb/bfd/libpei.h \
	../../../binutils-gdb/bfd/libxcoff.h \
	../../../binutils-gdb/bfd/linker.c \
	../../../binutils-gdb/bfd/lynx-core.c \
	../../../binutils-gdb/bfd/mach-o-aarch64.c \
	../../../binutils-gdb/bfd/mach-o-arm.c \
	../../../binutils-gdb/bfd/mach-o-i386.c \
	../../../binutils-gdb/bfd/mach-o-x86-64.c \
	../../../binutils-gdb/bfd/mach-o.c \
	../../../binutils-gdb/bfd/mach-o.h \
	../../../binutils-gdb/bfd/merge.c \
	../../../binutils-gdb/bfd/mmo.c \
	../../../binutils-gdb/bfd/netbsd-core.c \
	../../../binutils-gdb/bfd/netbsd.h \
	../../../binutils-gdb/bfd/ns32k.h \
	../../../binutils-gdb/bfd/ns32knetbsd.c \
	../../../binutils-gdb/bfd/opncls.c \
	../../../binutils-gdb/bfd/osf-core.c \
	../../../binutils-gdb/bfd/pc532-mach.c \
	../../../binutils-gdb/bfd/pdb.c \
	../../../binutils-gdb/bfd/pdp11.c \
	../../../binutils-gdb/bfd/pe-aarch64.c \
	../../../binutils-gdb/bfd/pe-arm-wince.c \
	../../../binutils-gdb/bfd/pe-arm.c \
	../../../binutils-gdb/bfd/pe-i386.c \
	../../../binutils-gdb/bfd/pe-mcore.c \
	../../../binutils-gdb/bfd/pe-sh.c \
	../../../binutils-gdb/bfd/pe-x86_64.c \
	../../../binutils-gdb/bfd/pef-traceback.h \
	../../../binutils-gdb/bfd/pef.c \
	../../../binutils-gdb/bfd/pef.h \
	../../../binutils-gdb/bfd/pei-aarch64.c \
	../../../binutils-gdb/bfd/pei-arm-wince.c \
	../../../binutils-gdb/bfd/pei-arm.c \
	../../../binutils-gdb/bfd/pei-i386.c \
	../../../binutils-gdb/bfd/pei-ia64.c \
	../../../binutils-gdb/bfd/pei-loongarch64.c \
	../../../binutils-gdb/bfd/pei-mcore.c \
	../../../binutils-gdb/bfd/pei-riscv64.c \
	../../../binutils-gdb/bfd/pei-sh.c \
	../../../binutils-gdb/bfd/pei-x86_64.c \
	../../../binutils-gdb/bfd/peicode.h \
	../../../binutils-gdb/bfd/plugin.c \
	../../../binutils-gdb/bfd/plugin.h \
	../../../binutils-gdb/bfd/ppcboot.c \
	../../../binutils-gdb/bfd/reloc.c \
	../../../binutils-gdb/bfd/reloc16.c \
	../../../binutils-gdb/bfd/rs6000-core.c \
	../../../binutils-gdb/bfd/section.c \
	../../../binutils-gdb/bfd/simple.c \
	../../../binutils-gdb/bfd/som.c \
	../../../binutils-gdb/bfd/som.h \
	../../../binutils-gdb/bfd/srec.c \
	../../../binutils-gdb/bfd/stab-syms.c \
	../../../binutils-gdb/bfd/stabs.c \
	../../../binutils-gdb/bfd/syms.c \
	../../../binutils-gdb/bfd/sysdep.h \
	../../../binutils-gdb/bfd/targets.c \
	../../../binutils-gdb/bfd/tekhex.c \
	../../../binutils-gdb/bfd/trad-core.c \
	../../../binutils-gdb/bfd/vax1knetbsd.c \
	../../../binutils-gdb/bfd/vaxnetbsd.c \
	../../../binutils-gdb/bfd/verilog.c \
	../../../binutils-gdb/bfd/version.h \
	../../../binutils-gdb/bfd/vms-alpha.c \
	../../../binutils-gdb/bfd/vms-lib.c \
	../../../binutils-gdb/bfd/vms-misc.c \
	../../../binutils-gdb/bfd/vms.h \
	../../../binutils-gdb/bfd/wasm-module.c \
	../../../binutils-gdb/bfd/wasm-module.h \
	../../../binutils-gdb/bfd/xcofflink.c \
	../../../binutils-gdb/bfd/xcofflink.h \
	../../../binutils-gdb/bfd/xsym.c \
	../../../binutils-gdb/bfd/xsym.h \
	../../../binutils-gdb/bfd/xtensa-dynconfig.c \
	../../../binutils-gdb/bfd/xtensa-isa.c \
	../../../binutils-gdb/bfd/xtensa-modules.c 

# Note - the following line gets processed by bfd/configure and amended
# to contain the full list of build dir POTFILES.
BLD-POTFILES = \
	../bfdver.h \
	../elf32-aarch64.c \
	../elf32-ia64.c \
	../elf32-kvx.c \
	../elf32-loongarch.c \
	../elf32-riscv.c \
	../elf32-target.h \
	../elf64-aarch64.c \
	../elf64-ia64.c \
	../elf64-kvx.c \
	../elf64-loongarch.c \
	../elf64-riscv.c \
	../elf64-target.h \
	../pe-aarch64igen.c \
	../pe-loongarch64igen.c \
	../pe-riscv64igen.c \
	../peigen.c \
	../pepigen.c \
	../pex64igen.c \
	../targmatch.h 

CATALOGS = 
CATOBJEXT = 
INSTOBJEXT = 

.SUFFIXES:
.SUFFIXES: .c .o .po .pox .gmo .mo .msg .cat

.c.o:
	$(COMPILE) $<

.po.pox:
	$(MAKE) $(PACKAGE).pot
	$(MSGMERGE) $< $(srcdir)/$(PACKAGE).pot -o $*.pox

.po.mo:
	$(MSGFMT) -o $@ $<

.po.gmo:
	file=`echo $* | sed 's,.*/,,'`.gmo \
	  && rm -f $$file && $(GMSGFMT) -o $$file $<

.po.cat:
	sed -f ../intl/po2msg.sed < $< > $*.msg \
	  && rm -f $@ && $(GENCAT) $@ $*.msg


all: all-no

all-yes: $(CATALOGS) # $(PACKAGE).pot
all-no:

$(srcdir)/$(PACKAGE).pot: $(SRC-POTFILES) $(BLD-POTFILES)
	$(XGETTEXT) --default-domain=$(PACKAGE) \
	  --directory=$(top_srcdir) \
	  --add-comments --keyword=_ --keyword=N_ \
	  --msgid-bugs-address=https://sourceware.org/bugzilla/ \
	  --files-from=$(srcdir)/SRC-POTFILES.in 
	$(XGETTEXT) --default-domain=$(PACKAGE) \
	  --directory=.. \
	  --directory=. \
	  --add-comments --keyword=_ --keyword=N_ \
	  --join-existing \
	  --msgid-bugs-address=https://sourceware.org/bugzilla/ \
	  --files-from=$(srcdir)/BLD-POTFILES.in
	sed -e '/^#:/s,$(top_srcdir)/,,g' < $(PACKAGE).po > $@-t
	mv -f $@-t $@

$(srcdir)/cat-id-tbl.c: stamp-cat-id; @:
$(srcdir)/stamp-cat-id: $(PACKAGE).pot
	rm -f cat-id-tbl.tmp
	sed -f ../intl/po2tbl.sed $(srcdir)/$(PACKAGE).pot \
		| sed -e "s/@PACKAGE NAME@/$(PACKAGE)/" > cat-id-tbl.tmp
	if cmp -s cat-id-tbl.tmp $(srcdir)/cat-id-tbl.c; then \
	  rm cat-id-tbl.tmp; \
	else \
	  echo cat-id-tbl.c changed; \
	  rm -f $(srcdir)/cat-id-tbl.c; \
	  mv cat-id-tbl.tmp $(srcdir)/cat-id-tbl.c; \
	fi
	cd $(srcdir) && rm -f stamp-cat-id && echo timestamp > stamp-cat-id


install: install-exec install-data
install-exec:
install-info:
install-html:
install-dvi:
install-pdf:
install-ps:
install-data: install-data-no
install-data-no: all
install-data-yes: all
	if test -r $(MKINSTALLDIRS); then \
	  $(MKINSTALLDIRS) $(DESTDIR)$(datadir); \
	else \
	  $(top_srcdir)/mkinstalldirs $(DESTDIR)$(datadir); \
	fi
	@catalogs='$(CATALOGS)'; \
	for cat in $$catalogs; do \
	  cat=`basename $$cat`; \
	  case "$$cat" in \
	    *.gmo) destdir=$(gnulocaledir);; \
	    *)     destdir=$(localedir);; \
	  esac; \
	  lang=`echo $$cat | sed 's/\$(CATOBJEXT)$$//'`; \
	  dir=$(DESTDIR)$$destdir/$$lang/LC_MESSAGES; \
	  if test -r $(MKINSTALLDIRS); then \
	    $(MKINSTALLDIRS) $$dir; \
	  else \
	    $(top_srcdir)/mkinstalldirs $$dir; \
	  fi; \
	  if test -r $$cat; then \
	    $(INSTALL_DATA) $$cat $$dir/$(PACKAGE)$(INSTOBJEXT); \
	    echo "installing $$cat as $$dir/$(PACKAGE)$(INSTOBJEXT)"; \
	  else \
	    $(INSTALL_DATA) $(srcdir)/$$cat $$dir/$(PACKAGE)$(INSTOBJEXT); \
	    echo "installing $(srcdir)/$$cat as" \
		 "$$dir/$(PACKAGE)$(INSTOBJEXT)"; \
	  fi; \
	  if test -r $$cat.m; then \
	    $(INSTALL_DATA) $$cat.m $$dir/$(PACKAGE)$(INSTOBJEXT).m; \
	    echo "installing $$cat.m as $$dir/$(PACKAGE)$(INSTOBJEXT).m"; \
	  else \
	    if test -r $(srcdir)/$$cat.m ; then \
	      $(INSTALL_DATA) $(srcdir)/$$cat.m \
		$$dir/$(PACKAGE)$(INSTOBJEXT).m; \
	      echo "installing $(srcdir)/$$cat as" \
		   "$$dir/$(PACKAGE)$(INSTOBJEXT).m"; \
	    else \
	      true; \
	    fi; \
	  fi; \
	done
	if test "$(PACKAGE)" = "gettext"; then \
	  if test -r $(MKINSTALLDIRS); then \
	    $(MKINSTALLDIRS) $(DESTDIR)$(gettextsrcdir); \
	  else \
	    $(top_srcdir)/mkinstalldirs $(DESTDIR)$(gettextsrcdir); \
	  fi; \
	  $(INSTALL_DATA) $(srcdir)/Makefile.in.in \
			  $(DESTDIR)$(gettextsrcdir)/Makefile.in.in; \
	else \
	  : ; \
	fi

# Define this as empty until I found a useful application.
installcheck:

uninstall:
	catalogs='$(CATALOGS)'; \
	for cat in $$catalogs; do \
	  cat=`basename $$cat`; \
	  lang=`echo $$cat | sed 's/\$(CATOBJEXT)$$//'`; \
	  rm -f $(DESTDIR)$(localedir)/$$lang/LC_MESSAGES/$(PACKAGE)$(INSTOBJEXT); \
	  rm -f $(DESTDIR)$(localedir)/$$lang/LC_MESSAGES/$(PACKAGE)$(INSTOBJEXT).m; \
	  rm -f $(DESTDIR)$(gnulocaledir)/$$lang/LC_MESSAGES/$(PACKAGE)$(INSTOBJEXT); \
	  rm -f $(DESTDIR)$(gnulocaledir)/$$lang/LC_MESSAGES/$(PACKAGE)$(INSTOBJEXT).m; \
	done
	rm -f $(DESTDIR)$(gettextsrcdir)/po-Makefile.in.in

check: all

cat-id-tbl.o: ../intl/libgettext.h

html dvi pdf ps info tags TAGS ID:

mostlyclean:
	rm -f core core.* *.pox $(PACKAGE).po *.old.po cat-id-tbl.tmp
	rm -fr *.o

clean: mostlyclean

distclean: clean
	rm -f Makefile Makefile.in *.mo *.msg *.cat *.cat.m
	rm -f SRC-POTFILES BLD-POTFILES 

maintainer-clean: distclean
	@echo "This command is intended for maintainers to use;"
	@echo "it deletes files that may require special tools to rebuild."
	rm -f $(GMOFILES) SRC-POTFILES.in BLD-POTFILES.in

distdir = ../$(PACKAGE)-$(VERSION)/$(subdir)
dist distdir: update-po $(DISTFILES)
	dists="$(DISTFILES)"; \
	for file in $$dists; do \
	  ln $(srcdir)/$$file $(distdir) 2> /dev/null \
	    || cp -p $(srcdir)/$$file $(distdir); \
	done

update-po: Makefile
	$(MAKE) $(PACKAGE).pot
	PATH=`pwd`/../src:$$PATH; \
	cd $(srcdir); \
	catalogs='$(CATALOGS)'; \
	for cat in $$catalogs; do \
	  cat=`basename $$cat`; \
	  lang=`echo $$cat | sed 's/\$(CATOBJEXT)$$//'`; \
	  mv $$lang.po $$lang.old.po; \
	  echo "$$lang:"; \
	  if $(MSGMERGE) $$lang.old.po $(PACKAGE).pot -o $$lang.po; then \
	    rm -f $$lang.old.po; \
	  else \
	    echo "msgmerge for $$cat failed!"; \
	    rm -f $$lang.po; \
	    mv $$lang.old.po $$lang.po; \
	  fi; \
	done

SRC-POTFILES: SRC-POTFILES.in
	( if test 'x$(srcdir)' != 'x.'; then \
	    posrcprefix='$(top_srcdir)/'; \
	  else \
	    posrcprefix="../"; \
	  fi; \
	  rm -f $@-t $@ \
	    && (sed -e '/^#/d' \
	            -e '/^[ 	]*$$/d' \
		    -e "s@.*@	$$posrcprefix& \\\\@" < $(srcdir)/$@.in \
		| sed -e '$$s/\\$$//') > $@-t \
	    && chmod a-w $@-t \
	    && mv $@-t $@ )

BLD-POTFILES: BLD-POTFILES.in
	  ( rm -f $@-t $@ \
	    && (sed -e '/^#/d' \
	            -e '/^[ 	]*$$/d' \
		    -e "s@.*@	../& \\\\@" < $(srcdir)/$@.in \
		| sed -e '$$s/\\$$//') > $@-t \
	    && chmod a-w $@-t \
	    && mv $@-t $@ )

SRC-POTFILES.in: # ../Makefile
	cd .. && $(MAKE) po/SRC-POTFILES.in

BLD-POTFILES.in: # ../Makefile
	cd .. && $(MAKE) po/BLD-POTFILES.in

# Note - The presence of SRC-POTFILES and BLD-POTFILES as dependencies
# here breaks the implementation of the 'distclean' rule for maintainers.
# This is because if 'make distclean' is run in the BFD directory, the
# Makefile there will be deleted before 'distclean' is made here, and so
# the dependency SRC-POTFILES -> SRC-POTFILES.in -> ../Makefile cannot
# be satisfied.
#
# The SRC-POTFILES and BLD-POTFILES dependencies cannot be removed,
# however since it is necessary that these files be built during
# *configure* time, so that configure can insert them into the
# po/Makefile that it is creating, so that the Makefile will have
# the correct dependencies.
Makefile: Make-in ../config.status SRC-POTFILES BLD-POTFILES
	cd .. \
	  && CONFIG_FILES=$(subdir)/Makefile.in:$(subdir)/Make-in \
	     CONFIG_HEADERS= $(SHELL) ./config.status

# Tell versions [3.59,3.63) of GNU make not to export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
